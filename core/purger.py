"""
PurePurge – Purger Module
=========================
Build and execute deep-removal commands for APT, Snap, and Flatpak packages.

Every public ``purge_*`` function:
  1. Validates the target against the safeguards whitelist.
  2. Constructs a deterministic sequence of shell commands.
  3. Executes them through **pkexec** so the user sees a single polkit
     authentication prompt (no embedded passwords, no ``sudo`` in scripts).
  4. Returns a :class:`PurgeResult` with stdout/stderr and success status.
"""

from __future__ import annotations

import logging
import os
import shlex
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from core.safeguards import (
    filter_safe_apt,
    filter_safe_flatpaks,
    filter_safe_snaps,
    is_essential_apt,
    is_essential_flatpak,
    is_essential_snap,
)

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
# Result container
# ──────────────────────────────────────────────────────────────────────

@dataclass
class PurgeResult:
    """Outcome of a purge operation."""

    success: bool
    commands_run: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    blocked_packages: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        status = "✔ completed" if self.success else "✘ failed"
        parts = [status]
        if self.blocked_packages:
            parts.append(
                f"  ⚠ blocked (essential): {', '.join(self.blocked_packages)}"
            )
        return "\n".join(parts)


# ──────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────

def _run_pkexec_script(commands: list[str], *, dry_run: bool = False) -> PurgeResult:
    """Write *commands* to a temp script, execute via ``pkexec bash``.

    Using a single pkexec invocation for the whole script means the user
    authenticates only once.

    Parameters
    ----------
    commands:
        Shell command strings (one per logical step).
    dry_run:
        If ``True``, return the result with the commands that *would* run
        but do not actually execute anything.
    """
    result = PurgeResult(success=True, commands_run=list(commands))

    if dry_run:
        log.info("[dry-run] Would execute:\n%s", "\n".join(commands))
        return result

    # Build a self-deleting temporary script.
    script_lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        *commands,
    ]
    script_text = "\n".join(script_lines) + "\n"

    tmp_fd, tmp_path = tempfile.mkstemp(prefix="purepurge_", suffix=".sh")
    try:
        os.write(tmp_fd, script_text.encode())
        os.close(tmp_fd)
        os.chmod(tmp_path, 0o700)

        log.info("Executing purge script via pkexec: %s", tmp_path)
        proc = subprocess.run(
            ["pkexec", "bash", tmp_path],
            capture_output=True,
            text=True,
            timeout=600,  # 10 min hard limit
        )
        result.stdout = proc.stdout
        result.stderr = proc.stderr
        result.success = proc.returncode == 0

        if proc.returncode != 0:
            log.error(
                "Purge script exited %d:\nSTDOUT: %s\nSTDERR: %s",
                proc.returncode,
                proc.stdout,
                proc.stderr,
            )
    except subprocess.TimeoutExpired:
        log.error("Purge script timed out after 600 s")
        result.success = False
        result.stderr = "Purge script timed out after 600 seconds."
    except FileNotFoundError:
        log.error("pkexec not found – is polkit installed?")
        result.success = False
        result.stderr = (
            "pkexec not found. Please install policykit-1:\n"
            "  sudo apt install policykit-1"
        )
    finally:
        # Always clean up the temp script.
        Path(tmp_path).unlink(missing_ok=True)

    return result


def _quote(tokens: Sequence[str]) -> str:
    """Shell-quote a list of tokens into a single command string."""
    return " ".join(shlex.quote(t) for t in tokens)


# ──────────────────────────────────────────────────────────────────────
# APT purge
# ──────────────────────────────────────────────────────────────────────

def purge_apt(
    packages: Sequence[str],
    *,
    clean_repo: bool = True,
    scrub_residuals: bool = True,
    dry_run: bool = False,
) -> PurgeResult:
    """Deep-purge one or more APT packages and all traces they leave behind.

    Steps executed (in order):
      1. ``apt-get purge --autoremove -y <packages>``
      2. Remove residual-config packages (``dpkg -l | grep ^rc``).
      3. Remove any PPA / third-party ``.list`` files that *only* provided
         the removed packages.
      4. ``apt-get autoclean -y`` to drop cached ``.deb`` files.
      5. Scrub leftover config dirs from ``/etc`` and ``~/.config``.

    Parameters
    ----------
    packages:
        APT package names to remove.
    clean_repo:
        Also remove associated PPA/repo list files and signing keys.
    scrub_residuals:
        Also wipe residual config & cache files on disk.
    dry_run:
        Preview the commands without executing them.
    """
    removable, blocked = filter_safe_apt(packages)

    if not removable:
        return PurgeResult(
            success=True,
            blocked_packages=blocked,
            stderr="Nothing to remove (all packages are essential or list is empty).",
        )

    pkg_list = _quote(removable)
    commands: list[str] = []

    # 1. Core purge + autoremove
    commands.append(f"apt-get purge --autoremove -y {pkg_list}")

    # 2. Remove residual-config packages left by dpkg
    commands.append(
        "dpkg -l | awk '/^rc/ {print $2}' | xargs -r apt-get purge -y"
    )

    # 3. PPA / repo cleanup
    if clean_repo:
        for pkg in removable:
            # Remove any .list / .sources files whose filename contains the
            # package name (heuristic; covers the common ppa:<user>/<pkg> case).
            safe = shlex.quote(pkg)
            commands.append(
                f'find /etc/apt/sources.list.d/ -type f '
                f'\\( -name "*{safe}*" \\) -delete 2>/dev/null || true'
            )
            # Also try to remove the signing key added by add-apt-repository.
            commands.append(
                f'find /etc/apt/trusted.gpg.d/ /usr/share/keyrings/ '
                f'-type f \\( -name "*{safe}*" \\) -delete 2>/dev/null || true'
            )
        commands.append("apt-get update -qq")

    # 4. Clean cached .deb files
    commands.append("apt-get autoclean -y")

    # 5. Scrub residual config/cache directories
    if scrub_residuals:
        for pkg in removable:
            safe = shlex.quote(pkg)
            # System-wide config leftovers
            commands.append(f"rm -rf /etc/{safe} 2>/dev/null || true")
            # Per-user config & cache (run as the real user if known)
            real_home = os.environ.get("HOME", "/root")
            commands.append(
                f"rm -rf {shlex.quote(real_home)}/.config/{safe} "
                f"{shlex.quote(real_home)}/.local/share/{safe} "
                f"{shlex.quote(real_home)}/.cache/{safe} 2>/dev/null || true"
            )

    result = _run_pkexec_script(commands, dry_run=dry_run)
    result.blocked_packages = blocked
    return result


# ──────────────────────────────────────────────────────────────────────
# Snap purge
# ──────────────────────────────────────────────────────────────────────

def purge_snap(
    snaps: Sequence[str],
    *,
    scrub_residuals: bool = True,
    dry_run: bool = False,
) -> PurgeResult:
    """Deep-purge one or more Snap packages.

    Steps executed:
      1. ``snap remove --purge <snap>``  (for each snap)
      2. Remove leftover ``~/snap/<snap>`` user-data directories.
      3. Remove ``/var/snap/<snap>`` system-data directories.
      4. Clear cached snap revisions from ``/var/lib/snapd/cache``.

    Parameters
    ----------
    snaps:
        Snap package names to remove.
    scrub_residuals:
        Also wipe leftover snap data directories.
    dry_run:
        Preview the commands without executing them.
    """
    removable, blocked = filter_safe_snaps(snaps)

    if not removable:
        return PurgeResult(
            success=True,
            blocked_packages=blocked,
            stderr="Nothing to remove (all snaps are essential or list is empty).",
        )

    commands: list[str] = []

    for snap in removable:
        safe = shlex.quote(snap)
        # 1. Core removal (--purge removes revisions + data)
        commands.append(f"snap remove --purge {safe}")

    if scrub_residuals:
        real_home = os.environ.get("HOME", "/root")
        for snap in removable:
            safe = shlex.quote(snap)
            # 2. User data
            commands.append(
                f"rm -rf {shlex.quote(real_home)}/snap/{safe} 2>/dev/null || true"
            )
            # 3. System data
            commands.append(f"rm -rf /var/snap/{safe} 2>/dev/null || true")

        # 4. Prune cached .snap files that are no longer referenced
        commands.append(
            "find /var/lib/snapd/cache/ -type f -name '*.snap' -delete "
            "2>/dev/null || true"
        )

    result = _run_pkexec_script(commands, dry_run=dry_run)
    result.blocked_packages = blocked
    return result


# ──────────────────────────────────────────────────────────────────────
# Flatpak purge
# ──────────────────────────────────────────────────────────────────────

def purge_flatpak(
    refs: Sequence[str],
    *,
    scrub_residuals: bool = True,
    dry_run: bool = False,
) -> PurgeResult:
    """Deep-purge one or more Flatpak applications.

    Steps executed:
      1. ``flatpak uninstall --delete-data -y <ref>``  (per ref)
      2. ``flatpak uninstall --unused -y``  (clean up orphaned runtimes)
      3. Remove leftover ``~/.var/app/<ref>`` data directories.
      4. Clear the Flatpak system cache for the removed refs.

    Parameters
    ----------
    refs:
        Flatpak application IDs (e.g. ``com.spotify.Client``).
    scrub_residuals:
        Also wipe leftover user/system data directories.
    dry_run:
        Preview the commands without executing them.
    """
    removable, blocked = filter_safe_flatpaks(refs)

    if not removable:
        return PurgeResult(
            success=True,
            blocked_packages=blocked,
            stderr="Nothing to remove (all refs are essential or list is empty).",
        )

    commands: list[str] = []

    for ref in removable:
        safe = shlex.quote(ref)
        # 1. Remove the app and its data
        commands.append(f"flatpak uninstall --delete-data -y {safe}")

    # 2. Prune unused runtimes / extensions
    commands.append("flatpak uninstall --unused -y")

    if scrub_residuals:
        real_home = os.environ.get("HOME", "/root")
        for ref in removable:
            safe = shlex.quote(ref)
            # 3. Per-user data directory
            commands.append(
                f"rm -rf {shlex.quote(real_home)}/.var/app/{safe} 2>/dev/null || true"
            )
            # 4. System-wide app data
            commands.append(
                f"rm -rf /var/lib/flatpak/app/{safe} 2>/dev/null || true"
            )

    result = _run_pkexec_script(commands, dry_run=dry_run)
    result.blocked_packages = blocked
    return result
