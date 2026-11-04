"""
PurePurge – Confirmation / Inspection Modal
============================================
A dialog shown before any purge operation.  It lets the user inspect
**exactly** what will be affected:

  • Files & directories to be removed
  • Configuration paths to be scrubbed
  • Repository / PPA entries to be deleted
  • Commands that will be executed

The user must explicitly click **"Confirm Purge"** to proceed.
"""

from __future__ import annotations

import logging
import os
import shlex
import subprocess
from typing import Sequence

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QColor, QFont, QIcon
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpacerItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.scanner import AppEntry, PackageSource

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
# Colour tokens (must stay in sync with dashboard.py)
# ──────────────────────────────────────────────────────────────────────
_CLR_BG          = "#1a1a2e"
_CLR_SURFACE     = "#16213e"
_CLR_SURFACE_ALT = "#1c2a4a"
_CLR_ACCENT      = "#e94560"
_CLR_ACCENT_HOVER = "#ff6b81"
_CLR_TEXT        = "#eaeaea"
_CLR_TEXT_DIM    = "#8892a8"
_CLR_BORDER      = "#2a2a4a"
_CLR_WARN        = "#ffcc00"
_CLR_GREEN       = "#10ac84"
_CLR_RED         = "#e94560"

_STYLE = f"""
QDialog {{
    background-color: {_CLR_BG};
}}
QLabel {{
    color: {_CLR_TEXT};
}}
QTabWidget::pane {{
    background-color: {_CLR_SURFACE};
    border: 1px solid {_CLR_BORDER};
    border-radius: 6px;
    top: -1px;
}}
QTabBar::tab {{
    background-color: {_CLR_SURFACE};
    color: {_CLR_TEXT_DIM};
    border: 1px solid {_CLR_BORDER};
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 6px 18px;
    margin-right: 2px;
    font-size: 12px;
}}
QTabBar::tab:selected {{
    background-color: {_CLR_SURFACE_ALT};
    color: {_CLR_TEXT};
    font-weight: 600;
}}
QTreeWidget {{
    background-color: {_CLR_SURFACE};
    color: {_CLR_TEXT};
    border: none;
    font-size: 13px;
    outline: none;
}}
QTreeWidget::item {{
    padding: 4px 6px;
    border-bottom: 1px solid {_CLR_BORDER};
}}
QTreeWidget::item:hover {{
    background-color: {_CLR_SURFACE_ALT};
}}
QHeaderView::section {{
    background-color: {_CLR_SURFACE};
    color: {_CLR_TEXT_DIM};
    border: none;
    border-bottom: 1px solid {_CLR_BORDER};
    padding: 6px 10px;
    font-size: 11px;
    font-weight: 600;
}}
QScrollBar:vertical {{
    background: {_CLR_SURFACE};
    width: 6px;
}}
QScrollBar::handle:vertical {{
    background: {_CLR_BORDER};
    border-radius: 3px;
    min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
"""


# ──────────────────────────────────────────────────────────────────────
# Trace inspection helpers
# ──────────────────────────────────────────────────────────────────────

def _find_apt_traces(package: str) -> dict[str, list[str]]:
    """Return a mapping of trace categories → file paths for an APT package."""
    traces: dict[str, list[str]] = {
        "Installed files": [],
        "Config files": [],
        "Repo / PPA entries": [],
        "Cache files": [],
    }

    # Installed files via dpkg -L
    try:
        proc = subprocess.run(
            ["dpkg", "-L", package],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0:
            traces["Installed files"] = [
                p for p in proc.stdout.strip().splitlines() if os.path.exists(p)
            ]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Config paths
    home = os.environ.get("HOME", "/root")
    for candidate in (
        f"/etc/{package}",
        f"{home}/.config/{package}",
        f"{home}/.local/share/{package}",
        f"{home}/.cache/{package}",
    ):
        if os.path.exists(candidate):
            traces["Config files"].append(candidate)

    # PPA / repo list files
    for search_dir in ("/etc/apt/sources.list.d", "/etc/apt/trusted.gpg.d", "/usr/share/keyrings"):
        if os.path.isdir(search_dir):
            for f in os.listdir(search_dir):
                if package.lower() in f.lower():
                    traces["Repo / PPA entries"].append(os.path.join(search_dir, f))

    # Cached .deb files
    cache_dir = "/var/cache/apt/archives"
    if os.path.isdir(cache_dir):
        try:
            for f in os.listdir(cache_dir):
                if f.startswith(package) and f.endswith(".deb"):
                    traces["Cache files"].append(os.path.join(cache_dir, f))
        except PermissionError:
            pass

    return traces


def _find_snap_traces(snap_name: str) -> dict[str, list[str]]:
    """Return trace categories for a Snap package."""
    traces: dict[str, list[str]] = {
        "Snap data": [],
        "User data": [],
        "Cache": [],
    }
    home = os.environ.get("HOME", "/root")

    for path in (f"/var/snap/{snap_name}",):
        if os.path.exists(path):
            traces["Snap data"].append(path)

    for path in (f"{home}/snap/{snap_name}",):
        if os.path.exists(path):
            traces["User data"].append(path)

    cache_dir = "/var/lib/snapd/cache"
    if os.path.isdir(cache_dir):
        try:
            for f in os.listdir(cache_dir):
                if snap_name in f:
                    traces["Cache"].append(os.path.join(cache_dir, f))
        except PermissionError:
            pass

    return traces


def _find_flatpak_traces(ref: str) -> dict[str, list[str]]:
    """Return trace categories for a Flatpak application."""
    traces: dict[str, list[str]] = {
        "App data": [],
        "User data": [],
    }
    home = os.environ.get("HOME", "/root")

    for path in (f"/var/lib/flatpak/app/{ref}",):
        if os.path.exists(path):
            traces["App data"].append(path)

    for path in (
        f"{home}/.var/app/{ref}",
        f"{home}/.local/share/flatpak/app/{ref}",
    ):
        if os.path.exists(path):
            traces["User data"].append(path)

    return traces


def _build_commands_preview(apps: Sequence[AppEntry]) -> list[str]:
    """Return the list of shell commands that will be executed."""
    commands: list[str] = []
    apt_pkgs = [a.package_id for a in apps if a.source == PackageSource.APT]
    snaps    = [a.package_id for a in apps if a.source == PackageSource.SNAP]
    flatpaks = [a.package_id for a in apps if a.source == PackageSource.FLATPAK]

    if apt_pkgs:
        pkg_str = " ".join(shlex.quote(p) for p in apt_pkgs)
        commands.append(f"apt-get purge --autoremove -y {pkg_str}")
        commands.append("dpkg -l | awk '/^rc/ {print $2}' | xargs -r apt-get purge -y")
        commands.append("apt-get autoclean -y")

    for s in snaps:
        commands.append(f"snap remove --purge {shlex.quote(s)}")

    for f in flatpaks:
        commands.append(f"flatpak uninstall --delete-data -y {shlex.quote(f)}")
    if flatpaks:
        commands.append("flatpak uninstall --unused -y")

    return commands


# ──────────────────────────────────────────────────────────────────────
# The modal dialog
# ──────────────────────────────────────────────────────────────────────

class ConfirmModal(QDialog):
    """Inspection & confirmation dialog for purge operations.

    Shows a tabbed view:
      • **Overview** – summary of selected apps and total traces
      • **Files & Configs** – tree of every file / directory to be removed
      • **Commands** – exact shell commands that will be executed
    """

    def __init__(
        self,
        apps: Sequence[AppEntry],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Confirm Purge")
        self.setMinimumSize(700, 520)
        self.resize(780, 560)
        self.setModal(True)
        self.setStyleSheet(_STYLE)

        self._apps = list(apps)
        self._traces: dict[str, dict[str, list[str]]] = {}
        self._commands: list[str] = []

        self._inspect()
        self._build_ui()

    # ── Inspection ───────────────────────────────────────────────────

    def _inspect(self) -> None:
        """Pre-compute traces and command preview for all selected apps."""
        for app in self._apps:
            if app.source == PackageSource.APT:
                self._traces[app.package_id] = _find_apt_traces(app.package_id)
            elif app.source == PackageSource.SNAP:
                self._traces[app.package_id] = _find_snap_traces(app.package_id)
            elif app.source == PackageSource.FLATPAK:
                self._traces[app.package_id] = _find_flatpak_traces(app.package_id)

        self._commands = _build_commands_preview(self._apps)

    # ── UI ───────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(14)

        # ── Warning header ───────────────────────────────────────────
        warn_frame = QFrame()
        warn_frame.setStyleSheet(
            f"background-color: rgba(233,69,96,0.12); "
            f"border: 1px solid {_CLR_ACCENT}; border-radius: 8px;"
        )
        warn_layout = QHBoxLayout(warn_frame)
        warn_layout.setContentsMargins(14, 10, 14, 10)

        warn_icon = QLabel("⚠")
        warn_icon.setFont(self._font(18))
        warn_icon.setFixedWidth(28)
        warn_layout.addWidget(warn_icon)

        total_files = sum(
            len(paths) for cats in self._traces.values() for paths in cats.values()
        )
        warn_text = QLabel(
            f"<b>{len(self._apps)}</b> application(s) will be permanently removed.  "
            f"<b>{total_files}</b> file(s) / directories will be deleted."
        )
        warn_text.setWordWrap(True)
        warn_text.setFont(self._font(12))
        warn_text.setStyleSheet(f"color: {_CLR_TEXT};")
        warn_layout.addWidget(warn_text, stretch=1)
        layout.addWidget(warn_frame)

        # ── Tabs ─────────────────────────────────────────────────────
        tabs = QTabWidget()
        tabs.addTab(self._build_overview_tab(), "Overview")
        tabs.addTab(self._build_files_tab(), "Files && Configs")
        tabs.addTab(self._build_commands_tab(), "Commands")
        layout.addWidget(tabs, stretch=1)

        # ── Action buttons ───────────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        btn_cancel = QPushButton("Cancel")
        btn_cancel.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_cancel.setFixedHeight(36)
        btn_cancel.setStyleSheet(self._btn_style(secondary=True))
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)

        btn_confirm = QPushButton("🗑  Confirm Purge")
        btn_confirm.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_confirm.setFixedHeight(36)
        btn_confirm.setStyleSheet(self._btn_style())
        btn_confirm.clicked.connect(self.accept)
        btn_row.addWidget(btn_confirm)

        layout.addLayout(btn_row)

    # ── Tab builders ─────────────────────────────────────────────────

    def _build_overview_tab(self) -> QWidget:
        """Summary list of selected apps with source badges."""
        tree = QTreeWidget()
        tree.setHeaderLabels(["Application", "Package ID", "Source", "Traces"])
        tree.setRootIsDecorated(False)
        tree.setAlternatingRowColors(True)
        tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        tree.header().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)

        for app in self._apps:
            traces = self._traces.get(app.package_id, {})
            trace_count = sum(len(v) for v in traces.values())

            item = QTreeWidgetItem([
                app.name,
                app.package_id,
                app.source.name.capitalize(),
                str(trace_count),
            ])
            # Colour the source text
            src_colors = {
                PackageSource.APT:     "#e94560",
                PackageSource.SNAP:    "#0abde3",
                PackageSource.FLATPAK: "#10ac84",
            }
            item.setForeground(2, QColor(src_colors.get(app.source, _CLR_TEXT)))
            if app.icon:
                icon = QIcon.fromTheme(app.icon)
                if not icon.isNull():
                    item.setIcon(0, icon)
            tree.addTopLevelItem(item)

        return tree

    def _build_files_tab(self) -> QWidget:
        """Hierarchical tree: Package → Category → file paths."""
        tree = QTreeWidget()
        tree.setHeaderLabels(["Path / Category", "Type"])
        tree.setAlternatingRowColors(True)
        tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)

        for app in self._apps:
            traces = self._traces.get(app.package_id, {})

            # Top-level: package name
            pkg_node = QTreeWidgetItem([
                f"{app.name}  ({app.package_id})",
                app.source.name,
            ])
            pkg_node.setFont(0, self._font(12, bold=True))
            tree.addTopLevelItem(pkg_node)

            if not any(traces.values()):
                empty = QTreeWidgetItem(["(no traces detected)", ""])
                empty.setForeground(0, QColor(_CLR_TEXT_DIM))
                pkg_node.addChild(empty)
                continue

            for category, paths in traces.items():
                if not paths:
                    continue
                cat_node = QTreeWidgetItem([f"{category}  ({len(paths)})", ""])
                cat_node.setFont(0, self._font(11, bold=True))
                cat_node.setForeground(0, QColor(_CLR_WARN))
                pkg_node.addChild(cat_node)

                for path in paths:
                    kind = "dir" if os.path.isdir(path) else "file"
                    file_node = QTreeWidgetItem([path, kind])
                    file_node.setForeground(0, QColor(_CLR_TEXT_DIM))
                    cat_node.addChild(file_node)

            pkg_node.setExpanded(True)

        return tree

    def _build_commands_tab(self) -> QWidget:
        """Read-only list of exact shell commands that will be executed."""
        container = QWidget()
        v = QVBoxLayout(container)
        v.setContentsMargins(8, 8, 8, 8)
        v.setSpacing(6)

        info = QLabel(
            "The following commands will be executed through <b>pkexec</b> "
            "(you will authenticate once via polkit):"
        )
        info.setWordWrap(True)
        info.setFont(self._font(11))
        info.setStyleSheet(f"color: {_CLR_TEXT_DIM}; padding-bottom: 4px;")
        v.addWidget(info)

        tree = QTreeWidget()
        tree.setHeaderLabels(["#", "Command"])
        tree.setRootIsDecorated(False)
        tree.setAlternatingRowColors(True)
        tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        for i, cmd in enumerate(self._commands, 1):
            item = QTreeWidgetItem([str(i), cmd])
            item.setFont(1, self._mono_font(11))
            tree.addTopLevelItem(item)

        v.addWidget(tree, stretch=1)
        return container

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _font(size: int, bold: bool = False) -> QFont:
        f = QFont()
        f.setPointSize(size)
        if bold:
            f.setBold(True)
        return f

    @staticmethod
    def _mono_font(size: int) -> QFont:
        f = QFont("Monospace")
        f.setStyleHint(QFont.StyleHint.Monospace)
        f.setPointSize(size)
        return f

    @staticmethod
    def _btn_style(secondary: bool = False) -> str:
        if secondary:
            return (
                f"QPushButton {{"
                f"  background-color: {_CLR_SURFACE}; color: {_CLR_TEXT};"
                f"  border: 1px solid {_CLR_BORDER}; border-radius: 8px;"
                f"  padding: 0 22px; font-size: 13px; font-weight: 600;"
                f"}}"
                f"QPushButton:hover {{ background-color: {_CLR_SURFACE_ALT}; }}"
            )
        return (
            f"QPushButton {{"
            f"  background-color: {_CLR_RED}; color: {_CLR_TEXT};"
            f"  border: none; border-radius: 8px;"
            f"  padding: 0 24px; font-size: 13px; font-weight: 700;"
            f"}}"
            f"QPushButton:hover {{ background-color: {_CLR_ACCENT_HOVER}; }}"
        )
