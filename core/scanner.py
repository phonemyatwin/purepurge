"""
PurePurge – Scanner Module
==========================
Discovers installed applications across three packaging ecosystems and
returns them as a unified list of :class:`AppEntry` objects.

Scanning strategy
-----------------
* **APT** – walks ``/usr/share/applications/*.desktop`` files, parses their
  ``Name``, ``Icon``, and ``Exec`` fields, then resolves each ``.desktop``
  file back to its owning dpkg package via ``dpkg -S``.  Packages flagged
  ``Essential: yes`` or on the safeguards whitelist are tagged accordingly.
* **Snap** – calls ``snap list`` and enriches each result with its
  ``.desktop`` file (if present under ``/var/lib/snapd/desktop/applications``).
* **Flatpak** – calls ``flatpak list --app --columns=…`` and enriches each
  result with its ``.desktop`` file (if present under
  ``/var/lib/flatpak/exports/share/applications`` or the per-user path).
"""

from __future__ import annotations

import configparser
import logging
import os
import subprocess
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional

from core.safeguards import is_essential_apt, is_essential_flatpak, is_essential_snap

log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────

class PackageSource(Enum):
    """Which packaging system owns the application."""
    APT = auto()
    SNAP = auto()
    FLATPAK = auto()


@dataclass
class AppEntry:
    """Unified representation of an installed application."""

    # Display information
    name: str                              # Human-readable name (from .desktop or package)
    icon: str = ""                         # Icon name or path
    description: str = ""                  # One-line summary

    # Package identity
    package_id: str = ""                   # dpkg package name / snap name / flatpak ref
    source: PackageSource = PackageSource.APT
    version: str = ""
    installed_size: str = ""               # Human-readable size string

    # .desktop file this entry was discovered from (may be empty)
    desktop_file: str = ""

    # Safety flags
    is_essential: bool = False             # On the safeguards whitelist
    is_removable: bool = True              # Computed: not essential & has a package_id

    def __post_init__(self) -> None:
        self.is_removable = bool(self.package_id) and not self.is_essential


# ──────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────

def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    """Run a command, returning the completed process (never raises)."""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            **kwargs,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        log.warning("Command failed: %s – %s", cmd, exc)
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr=str(exc))


def _parse_desktop_file(path: str | Path) -> dict[str, str]:
    """Extract useful keys from a ``.desktop`` file.

    Returns a dict with keys: ``Name``, ``Icon``, ``Exec``, ``Comment``,
    ``NoDisplay``, ``Type`` (all optional, missing keys → empty string).
    """
    result: dict[str, str] = {}
    parser = configparser.RawConfigParser()
    parser.optionxform = str  # preserve case
    try:
        parser.read(str(path), encoding="utf-8")
        section = "Desktop Entry"
        if parser.has_section(section):
            for key in ("Name", "Icon", "Exec", "Comment", "NoDisplay", "Type"):
                result[key] = parser.get(section, key, fallback="")
    except (configparser.Error, UnicodeDecodeError, OSError) as exc:
        log.debug("Could not parse %s: %s", path, exc)
    return result


def _resolve_dpkg_owner(filepath: str) -> str:
    """Return the dpkg package that owns *filepath*, or ``""``."""
    proc = _run(["dpkg", "-S", filepath])
    if proc.returncode == 0 and ":" in proc.stdout:
        # Output format: "package-name: /path/to/file"  (may include arch)
        raw = proc.stdout.strip().splitlines()[0].split(":")[0]
        # Strip architecture qualifier (e.g. "libc6:amd64" → "libc6")
        return raw.split(":")[0].strip()
    return ""


def _dpkg_installed_size(package: str) -> str:
    """Return human-readable installed size for a dpkg package."""
    proc = _run(["dpkg-query", "-W", "-f=${Installed-Size}", package])
    if proc.returncode == 0 and proc.stdout.strip():
        try:
            kb = int(proc.stdout.strip())
            if kb >= 1024:
                return f"{kb / 1024:.1f} MB"
            return f"{kb} KB"
        except ValueError:
            pass
    return ""


def _dpkg_description(package: str) -> str:
    """Return the one-line description for a dpkg package."""
    proc = _run(["dpkg-query", "-W", "-f=${Description}", package])
    if proc.returncode == 0 and proc.stdout.strip():
        # dpkg returns multi-line; take only the first synopsis line.
        return proc.stdout.strip().splitlines()[0]
    return ""


def _dpkg_version(package: str) -> str:
    """Return the installed version of a dpkg package."""
    proc = _run(["dpkg-query", "-W", "-f=${Version}", package])
    if proc.returncode == 0:
        return proc.stdout.strip()
    return ""


# ──────────────────────────────────────────────────────────────────────
# APT scanner
# ──────────────────────────────────────────────────────────────────────

_APT_DESKTOP_DIRS: list[str] = [
    "/usr/share/applications",
    "/usr/local/share/applications",
]


def scan_apt() -> list[AppEntry]:
    """Scan ``.desktop`` files and map each to its owning dpkg package.

    Only entries with ``Type=Application`` (and ``NoDisplay`` not ``true``)
    are included – this filters out actions, links, and hidden helpers.
    """
    entries: list[AppEntry] = []
    seen_packages: set[str] = set()

    for app_dir in _APT_DESKTOP_DIRS:
        dir_path = Path(app_dir)
        if not dir_path.is_dir():
            continue

        for desktop_path in sorted(dir_path.glob("*.desktop")):
            fields = _parse_desktop_file(desktop_path)

            # Skip non-application or hidden entries
            if fields.get("Type", "Application") != "Application":
                continue
            if fields.get("NoDisplay", "").lower() == "true":
                continue

            name = fields.get("Name", desktop_path.stem)
            if not name:
                continue

            # Resolve the dpkg package that shipped this .desktop file
            package = _resolve_dpkg_owner(str(desktop_path))
            if not package or package in seen_packages:
                # Skip .desktop files not owned by dpkg (e.g. manually
                # placed) or duplicates for the same package.
                if not package:
                    log.debug("No dpkg owner for %s – skipping", desktop_path)
                continue
            seen_packages.add(package)

            essential = is_essential_apt(package)

            entry = AppEntry(
                name=name,
                icon=fields.get("Icon", ""),
                description=_dpkg_description(package),
                package_id=package,
                source=PackageSource.APT,
                version=_dpkg_version(package),
                installed_size=_dpkg_installed_size(package),
                desktop_file=str(desktop_path),
                is_essential=essential,
            )
            entries.append(entry)

    log.info("APT scan found %d application(s)", len(entries))
    return entries


# ──────────────────────────────────────────────────────────────────────
# Snap scanner
# ──────────────────────────────────────────────────────────────────────

_SNAP_DESKTOP_DIRS: list[str] = [
    "/var/lib/snapd/desktop/applications",
]


def scan_snap() -> list[AppEntry]:
    """Scan installed snaps via ``snap list``.

    Enriches each snap with its ``.desktop`` file metadata when available.
    """
    proc = _run(["snap", "list"])
    if proc.returncode != 0:
        log.warning("'snap list' failed – snap may not be installed")
        return []

    entries: list[AppEntry] = []
    lines = proc.stdout.strip().splitlines()
    if len(lines) < 2:
        return entries

    # Parse the header to locate column positions
    header = lines[0]
    col_name = header.lower().find("name")
    col_version = header.lower().find("version")
    col_rev = header.lower().find("rev")
    col_notes = header.lower().find("notes")

    for line in lines[1:]:
        parts = line.split()
        if not parts:
            continue

        snap_name = parts[0]
        version = parts[1] if len(parts) > 1 else ""
        notes = parts[-1] if len(parts) > 4 else ""

        # Try to find a .desktop file for richer metadata
        desktop_fields: dict[str, str] = {}
        desktop_file = ""
        for d in _SNAP_DESKTOP_DIRS:
            candidates = list(Path(d).glob(f"{snap_name}_*.desktop")) if Path(d).is_dir() else []
            if candidates:
                desktop_file = str(candidates[0])
                desktop_fields = _parse_desktop_file(candidates[0])
                break

        display_name = desktop_fields.get("Name", snap_name)
        icon = desktop_fields.get("Icon", "")
        comment = desktop_fields.get("Comment", "")

        essential = is_essential_snap(snap_name)

        entry = AppEntry(
            name=display_name,
            icon=icon,
            description=comment,
            package_id=snap_name,
            source=PackageSource.SNAP,
            version=version,
            desktop_file=desktop_file,
            is_essential=essential,
        )
        entries.append(entry)

    log.info("Snap scan found %d package(s)", len(entries))
    return entries


# ──────────────────────────────────────────────────────────────────────
# Flatpak scanner
# ──────────────────────────────────────────────────────────────────────

_FLATPAK_DESKTOP_DIRS: list[str] = [
    "/var/lib/flatpak/exports/share/applications",
    os.path.expanduser("~/.local/share/flatpak/exports/share/applications"),
]


def scan_flatpak() -> list[AppEntry]:
    """Scan installed Flatpak apps via ``flatpak list --app``.

    Enriches each app with its ``.desktop`` file metadata when available.
    """
    proc = _run([
        "flatpak", "list", "--app",
        "--columns=application,name,version,installed-size,description",
    ])
    if proc.returncode != 0:
        log.warning("'flatpak list' failed – flatpak may not be installed")
        return []

    entries: list[AppEntry] = []
    for line in proc.stdout.strip().splitlines():
        # Columns are tab-separated
        cols = line.split("\t")
        if not cols or not cols[0].strip():
            continue

        ref = cols[0].strip()
        flat_name = cols[1].strip() if len(cols) > 1 else ref.rsplit(".", 1)[-1]
        version = cols[2].strip() if len(cols) > 2 else ""
        size = cols[3].strip() if len(cols) > 3 else ""
        description = cols[4].strip() if len(cols) > 4 else ""

        # Try to find a .desktop file for the icon
        desktop_file = ""
        icon = ""
        for d in _FLATPAK_DESKTOP_DIRS:
            candidate = Path(d) / f"{ref}.desktop"
            if candidate.is_file():
                desktop_file = str(candidate)
                desktop_fields = _parse_desktop_file(candidate)
                icon = desktop_fields.get("Icon", "")
                if not flat_name or flat_name == ref.rsplit(".", 1)[-1]:
                    flat_name = desktop_fields.get("Name", flat_name)
                if not description:
                    description = desktop_fields.get("Comment", "")
                break

        essential = is_essential_flatpak(ref)

        entry = AppEntry(
            name=flat_name,
            icon=icon,
            description=description,
            package_id=ref,
            source=PackageSource.FLATPAK,
            version=version,
            installed_size=size,
            desktop_file=desktop_file,
            is_essential=essential,
        )
        entries.append(entry)

    log.info("Flatpak scan found %d application(s)", len(entries))
    return entries


# ──────────────────────────────────────────────────────────────────────
# Unified scanner
# ──────────────────────────────────────────────────────────────────────

def scan_all() -> list[AppEntry]:
    """Scan APT, Snap, and Flatpak and return a merged list sorted by name.

    Each source is scanned independently; a failure in one source does not
    prevent the others from returning results.
    """
    results: list[AppEntry] = []

    for label, scanner in (("APT", scan_apt), ("Snap", scan_snap), ("Flatpak", scan_flatpak)):
        try:
            results.extend(scanner())
        except Exception:
            log.exception("Unexpected error scanning %s – skipping", label)

    results.sort(key=lambda e: e.name.lower())
    log.info("Total: %d application(s) across all sources", len(results))
    return results
