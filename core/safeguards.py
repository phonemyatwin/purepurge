"""
PurePurge – Safeguards Module
=============================
Maintains a whitelist of essential system packages / snaps / flatpaks that
must **never** be removed.  Every purge path checks against these lists
before building a removal command.

The whitelist uses two kinds of entries:
  • exact names   – matched with ``==``
  • glob patterns – matched with :func:`fnmatch.fnmatch` (e.g. ``linux-image-*``)
"""

from __future__ import annotations

import fnmatch
from typing import Iterable

# ──────────────────────────────────────────────────────────────────────
# APT / dpkg essential packages
# ──────────────────────────────────────────────────────────────────────
ESSENTIAL_APT_PACKAGES: frozenset[str] = frozenset(
    {
        # ── Desktop meta-packages ────────────────────────────────────
        "ubuntu-desktop",
        "ubuntu-desktop-minimal",
        "ubuntu-standard",
        "ubuntu-minimal",
        "ubuntu-server",
        # ── Init / boot / kernel ─────────────────────────────────────
        "systemd",
        "systemd-sysv",
        "init",
        "init-system-helpers",
        "grub-common",
        "grub-pc",
        "grub-efi-amd64",
        "grub-efi-amd64-signed",
        "shim-signed",
        # ── Core C library & loader ──────────────────────────────────
        "libc6",
        "libc-bin",
        "libstdc++6",
        # ── Package management ───────────────────────────────────────
        "apt",
        "dpkg",
        "apt-utils",
        "software-properties-common",
        "python3-apt",
        # ── Core utilities & shells ──────────────────────────────────
        "bash",
        "coreutils",
        "dash",
        "login",
        "passwd",
        "sudo",
        "util-linux",
        # ── Networking essentials ────────────────────────────────────
        "networkmanager",
        "network-manager",
        "iproute2",
        "ifupdown",
        "netplan.io",
        # ── Hardware / firmware ──────────────────────────────────────
        "udev",
        "dbus",
        "dbus-user-session",
        # ── Snap daemon (needed for snap ecosystem) ──────────────────
        "snapd",
        # ── Display / session ────────────────────────────────────────
        "gdm3",
        "xorg",
        "xserver-xorg",
        "wayland",
        "libwayland-client0",
        # ── Security ────────────────────────────────────────────────
        "apparmor",
        "polkitd",
        "policykit-1",
        # ── Python runtime (used by system tools) ────────────────────
        "python3",
        "python3-minimal",
    }
)

# Glob patterns for APT packages that span many version-suffixed names.
ESSENTIAL_APT_GLOBS: tuple[str, ...] = (
    "linux-image-*",
    "linux-headers-*",
    "linux-modules-*",
    "linux-firmware*",
    "libc6:*",          # multiarch variants
)

# ──────────────────────────────────────────────────────────────────────
# Snap essential packages
# ──────────────────────────────────────────────────────────────────────
ESSENTIAL_SNAPS: frozenset[str] = frozenset(
    {
        "bare",
        "core",
        "core18",
        "core20",
        "core22",
        "core24",
        "snapd",
        "gnome-42-2204",   # GNOME platform snap (Ubuntu 22.04+)
        "gnome-46-2404",   # GNOME platform snap (Ubuntu 24.04+)
        "gtk-common-themes",
    }
)

ESSENTIAL_SNAP_GLOBS: tuple[str, ...] = (
    "core*",
    "gnome-*-*",       # all GNOME platform snaps
)

# ──────────────────────────────────────────────────────────────────────
# Flatpak essential runtimes
# ──────────────────────────────────────────────────────────────────────
ESSENTIAL_FLATPAKS: frozenset[str] = frozenset(
    {
        "org.freedesktop.Platform",
        "org.freedesktop.Sdk",
        "org.gnome.Platform",
        "org.gnome.Sdk",
        "org.kde.Platform",
        "org.kde.Sdk",
        "org.gtk.Gtk3theme.Yaru",
    }
)

ESSENTIAL_FLATPAK_GLOBS: tuple[str, ...] = (
    "org.freedesktop.Platform.*",
    "org.freedesktop.Sdk.*",
    "org.gnome.Platform.*",
    "org.gnome.Sdk.*",
    "org.kde.Platform.*",
    "org.kde.Sdk.*",
)


# ──────────────────────────────────────────────────────────────────────
# Public helpers
# ──────────────────────────────────────────────────────────────────────

def _matches_any_glob(name: str, globs: Iterable[str]) -> bool:
    """Return ``True`` if *name* matches any of the given glob patterns."""
    return any(fnmatch.fnmatch(name, pat) for pat in globs)


def is_essential_apt(package: str) -> bool:
    """Check whether an APT package name is on the essential whitelist."""
    return (
        package in ESSENTIAL_APT_PACKAGES
        or _matches_any_glob(package, ESSENTIAL_APT_GLOBS)
    )


def is_essential_snap(snap: str) -> bool:
    """Check whether a snap name is on the essential whitelist."""
    return (
        snap in ESSENTIAL_SNAPS
        or _matches_any_glob(snap, ESSENTIAL_SNAP_GLOBS)
    )


def is_essential_flatpak(ref: str) -> bool:
    """Check whether a Flatpak ref is on the essential whitelist."""
    return (
        ref in ESSENTIAL_FLATPAKS
        or _matches_any_glob(ref, ESSENTIAL_FLATPAK_GLOBS)
    )


def filter_safe_apt(packages: Iterable[str]) -> tuple[list[str], list[str]]:
    """Partition *packages* into ``(removable, blocked)`` lists.

    Returns
    -------
    removable : list[str]
        Packages that are safe to purge.
    blocked : list[str]
        Packages that are on the essential whitelist and were rejected.
    """
    removable: list[str] = []
    blocked: list[str] = []
    for pkg in packages:
        (blocked if is_essential_apt(pkg) else removable).append(pkg)
    return removable, blocked


def filter_safe_snaps(snaps: Iterable[str]) -> tuple[list[str], list[str]]:
    """Partition *snaps* into ``(removable, blocked)`` lists."""
    removable: list[str] = []
    blocked: list[str] = []
    for snap in snaps:
        (blocked if is_essential_snap(snap) else removable).append(snap)
    return removable, blocked


def filter_safe_flatpaks(refs: Iterable[str]) -> tuple[list[str], list[str]]:
    """Partition Flatpak *refs* into ``(removable, blocked)`` lists."""
    removable: list[str] = []
    blocked: list[str] = []
    for ref in refs:
        (blocked if is_essential_flatpak(ref) else removable).append(ref)
    return removable, blocked
