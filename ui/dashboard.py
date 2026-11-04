"""
PurePurge – Dashboard Window
=============================
Main application window with:
  • Search bar for filtering by name / package ID
  • Package-type filter tags (All · APT · Snap · Flatpak)
  • Scrollable application list showing name, icon, source badge, and size
  • Selection → opens the confirmation / inspection modal before purging
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from PyQt6.QtCore import (
    QSize,
    QSortFilterProxyModel,
    Qt,
    QThread,
    pyqtSignal,
    pyqtSlot,
)
from PyQt6.QtGui import QColor, QFont, QIcon, QPainter, QPalette
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.scanner import AppEntry, PackageSource, scan_all

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
# Colour palette (dark, Ubuntu-flavoured)
# ──────────────────────────────────────────────────────────────────────
_CLR_BG          = "#1a1a2e"
_CLR_SURFACE     = "#16213e"
_CLR_SURFACE_ALT = "#1c2a4a"
_CLR_ACCENT      = "#e94560"
_CLR_ACCENT_HOVER = "#ff6b81"
_CLR_TEXT        = "#eaeaea"
_CLR_TEXT_DIM    = "#8892a8"
_CLR_BORDER      = "#2a2a4a"
_CLR_SEARCH_BG   = "#0f3460"
_CLR_TAG_ACTIVE  = _CLR_ACCENT
_CLR_TAG_INACTIVE = "#2a2a4a"
_CLR_ESSENTIAL   = "#ffcc00"

_BADGE_COLORS = {
    PackageSource.APT:     ("#e94560", "#1a1a2e"),  # bg, fg
    PackageSource.SNAP:    ("#0abde3", "#1a1a2e"),
    PackageSource.FLATPAK: ("#10ac84", "#1a1a2e"),
}

# ──────────────────────────────────────────────────────────────────────
# Stylesheet fragments
# ──────────────────────────────────────────────────────────────────────

_GLOBAL_STYLE = f"""
QMainWindow, QWidget#centralWidget {{
    background-color: {_CLR_BG};
}}
QLabel {{
    color: {_CLR_TEXT};
}}
QLineEdit#searchBar {{
    background-color: {_CLR_SEARCH_BG};
    color: {_CLR_TEXT};
    border: 1px solid {_CLR_BORDER};
    border-radius: 8px;
    padding: 8px 12px 8px 36px;       /* leave space for icon */
    font-size: 14px;
}}
QLineEdit#searchBar:focus {{
    border: 1px solid {_CLR_ACCENT};
}}
QTableWidget {{
    background-color: {_CLR_SURFACE};
    alternate-background-color: {_CLR_SURFACE_ALT};
    color: {_CLR_TEXT};
    border: none;
    gridline-color: {_CLR_BORDER};
    font-size: 13px;
    selection-background-color: {_CLR_ACCENT};
    selection-color: {_CLR_TEXT};
    outline: none;
}}
QTableWidget::item {{
    padding: 6px 10px;
    border-bottom: 1px solid {_CLR_BORDER};
}}
QTableWidget::item:hover {{
    background-color: {_CLR_SURFACE_ALT};
}}
QHeaderView::section {{
    background-color: {_CLR_SURFACE};
    color: {_CLR_TEXT_DIM};
    border: none;
    border-bottom: 2px solid {_CLR_BORDER};
    padding: 8px 10px;
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
}}
QScrollBar:vertical {{
    background: {_CLR_SURFACE};
    width: 8px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {_CLR_BORDER};
    border-radius: 4px;
    min-height: 30px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QProgressBar {{
    background-color: {_CLR_SURFACE};
    border: none;
    border-radius: 4px;
    text-align: center;
    color: {_CLR_TEXT};
    font-size: 12px;
}}
QProgressBar::chunk {{
    background-color: {_CLR_ACCENT};
    border-radius: 4px;
}}
"""


def _tag_style(active: bool) -> str:
    bg = _CLR_TAG_ACTIVE if active else _CLR_TAG_INACTIVE
    fg = _CLR_TEXT
    border = _CLR_ACCENT if active else _CLR_BORDER
    return (
        f"background-color: {bg}; color: {fg}; border: 1px solid {border}; "
        f"border-radius: 12px; padding: 5px 16px; font-size: 12px; "
        f"font-weight: {'700' if active else '500'};"
    )


# ──────────────────────────────────────────────────────────────────────
# Background scanner thread
# ──────────────────────────────────────────────────────────────────────

class _ScanWorker(QThread):
    """Runs the full scan off the main thread so the UI stays responsive."""

    finished = pyqtSignal(list)   # list[AppEntry]
    error    = pyqtSignal(str)

    def run(self) -> None:
        try:
            apps = scan_all()
            self.finished.emit(apps)
        except Exception as exc:
            log.exception("Scan failed")
            self.error.emit(str(exc))


# ──────────────────────────────────────────────────────────────────────
# Source-badge delegate (paints a coloured pill in the "Source" column)
# ──────────────────────────────────────────────────────────────────────

class _SourceBadgeDelegate(QStyledItemDelegate):
    """Custom delegate that renders the source column as a coloured pill."""

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index) -> None:
        text = index.data(Qt.ItemDataRole.DisplayRole)
        if text not in ("APT", "Snap", "Flatpak"):
            super().paint(painter, option, index)
            return

        source_map = {"APT": PackageSource.APT, "Snap": PackageSource.SNAP, "Flatpak": PackageSource.FLATPAK}
        bg_hex, fg_hex = _BADGE_COLORS.get(source_map[text], ("#555", "#fff"))

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Pill background
        font = QFont()
        font.setPointSize(9)
        font.setBold(True)
        painter.setFont(font)
        fm = painter.fontMetrics()
        tw = fm.horizontalAdvance(text) + 20
        th = fm.height() + 6
        rect = option.rect
        x = rect.x() + (rect.width() - tw) // 2
        y = rect.y() + (rect.height() - th) // 2

        from PyQt6.QtCore import QRectF
        pill = QRectF(x, y, tw, th)
        painter.setBrush(QColor(bg_hex))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(pill, th / 2, th / 2)

        # Text
        painter.setPen(QColor(fg_hex))
        painter.drawText(pill, Qt.AlignmentFlag.AlignCenter, text)
        painter.restore()

    def sizeHint(self, option, index) -> QSize:
        return QSize(80, 36)


# ──────────────────────────────────────────────────────────────────────
# Main dashboard window
# ──────────────────────────────────────────────────────────────────────

_COL_NAME   = 0
_COL_PKG    = 1
_COL_SOURCE = 2
_COL_VER    = 3
_COL_SIZE   = 4
_COL_COUNT  = 5

_HEADERS = ["Application", "Package ID", "Source", "Version", "Size"]


class Dashboard(QMainWindow):
    """PurePurge main window."""

    # Emitted when the user confirms removal via the inspection modal.
    purge_requested = pyqtSignal(list)  # list[AppEntry]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("PurePurge")
        self.setMinimumSize(960, 640)
        self.resize(1080, 720)

        self._apps: list[AppEntry] = []
        self._active_filter: str = "All"
        self._scan_worker: _ScanWorker | None = None

        self._build_ui()
        self.setStyleSheet(_GLOBAL_STYLE)
        self._start_scan()

    # ── UI construction ──────────────────────────────────────────────

    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("centralWidget")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        # ── Header ───────────────────────────────────────────────────
        header_row = QHBoxLayout()
        title = QLabel("PurePurge")
        title.setFont(self._make_font(22, bold=True))
        title.setStyleSheet(f"color: {_CLR_ACCENT};")
        header_row.addWidget(title)

        subtitle = QLabel("Zero-Trace Uninstaller")
        subtitle.setFont(self._make_font(11))
        subtitle.setStyleSheet(f"color: {_CLR_TEXT_DIM}; padding-top: 6px;")
        header_row.addWidget(subtitle)

        header_row.addStretch()

        self._status_label = QLabel("")
        self._status_label.setFont(self._make_font(11))
        self._status_label.setStyleSheet(f"color: {_CLR_TEXT_DIM};")
        header_row.addWidget(self._status_label)

        root.addLayout(header_row)

        # ── Search bar ───────────────────────────────────────────────
        self._search = QLineEdit()
        self._search.setObjectName("searchBar")
        self._search.setPlaceholderText("  🔍  Search applications…")
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._apply_filters)
        root.addWidget(self._search)

        # ── Filter tags ──────────────────────────────────────────────
        tag_row = QHBoxLayout()
        tag_row.setSpacing(8)
        self._tag_buttons: dict[str, QPushButton] = {}
        for label in ("All", "APT", "Snap", "Flatpak"):
            btn = QPushButton(label)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setFixedHeight(30)
            btn.clicked.connect(lambda checked, l=label: self._set_filter(l))
            tag_row.addWidget(btn)
            self._tag_buttons[label] = btn
        tag_row.addStretch()

        self._selected_count_label = QLabel("0 selected")
        self._selected_count_label.setFont(self._make_font(11))
        self._selected_count_label.setStyleSheet(f"color: {_CLR_TEXT_DIM};")
        tag_row.addWidget(self._selected_count_label)

        root.addLayout(tag_row)
        self._refresh_tags()

        # ── Progress bar (shown during scan) ─────────────────────────
        self._progress = QProgressBar()
        self._progress.setFixedHeight(18)
        self._progress.setRange(0, 0)  # indeterminate
        self._progress.setFormat("Scanning installed applications…")
        root.addWidget(self._progress)

        # ── Application table ────────────────────────────────────────
        self._table = QTableWidget()
        self._table.setColumnCount(_COL_COUNT)
        self._table.setHorizontalHeaderLabels(_HEADERS)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.setSortingEnabled(True)
        self._table.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

        # Column sizing
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(_COL_NAME,   QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(_COL_PKG,    QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(_COL_SOURCE, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(_COL_VER,    QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(_COL_SIZE,   QHeaderView.ResizeMode.ResizeToContents)
        self._table.setColumnWidth(_COL_SOURCE, 100)

        # Badge delegate for the Source column
        self._table.setItemDelegateForColumn(_COL_SOURCE, _SourceBadgeDelegate(self._table))

        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        root.addWidget(self._table, stretch=1)

        # ── Bottom action bar ────────────────────────────────────────
        action_row = QHBoxLayout()
        action_row.setSpacing(12)

        self._btn_refresh = QPushButton("↻  Refresh")
        self._btn_refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_refresh.setStyleSheet(self._action_btn_style(secondary=True))
        self._btn_refresh.setFixedHeight(38)
        self._btn_refresh.clicked.connect(self._start_scan)
        action_row.addWidget(self._btn_refresh)

        action_row.addStretch()

        self._btn_purge = QPushButton("🗑  Purge Selected")
        self._btn_purge.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_purge.setStyleSheet(self._action_btn_style())
        self._btn_purge.setFixedHeight(38)
        self._btn_purge.setEnabled(False)
        self._btn_purge.clicked.connect(self._on_purge_clicked)
        action_row.addWidget(self._btn_purge)

        root.addLayout(action_row)

    # ── Scanning ─────────────────────────────────────────────────────

    def _start_scan(self) -> None:
        self._progress.setVisible(True)
        self._table.setRowCount(0)
        self._status_label.setText("Scanning…")
        self._btn_refresh.setEnabled(False)
        self._btn_purge.setEnabled(False)

        self._scan_worker = _ScanWorker()
        self._scan_worker.finished.connect(self._on_scan_finished)
        self._scan_worker.error.connect(self._on_scan_error)
        self._scan_worker.start()

    @pyqtSlot(list)
    def _on_scan_finished(self, apps: list[AppEntry]) -> None:
        self._apps = apps
        self._progress.setVisible(False)
        self._btn_refresh.setEnabled(True)
        self._populate_table()
        counts = self._source_counts()
        self._status_label.setText(
            f"{len(apps)} apps  ·  "
            f"{counts.get('APT',0)} APT  ·  "
            f"{counts.get('SNAP',0)} Snap  ·  "
            f"{counts.get('FLATPAK',0)} Flatpak"
        )

    @pyqtSlot(str)
    def _on_scan_error(self, msg: str) -> None:
        self._progress.setVisible(False)
        self._btn_refresh.setEnabled(True)
        self._status_label.setText(f"⚠ Scan error: {msg}")

    # ── Table population ─────────────────────────────────────────────

    def _populate_table(self) -> None:
        search = self._search.text().strip().lower()
        filt = self._active_filter

        visible = [
            app for app in self._apps
            if self._matches_filter(app, filt, search)
        ]

        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(visible))

        for row, app in enumerate(visible):
            # Name
            name_item = QTableWidgetItem(app.name)
            if app.icon:
                icon = QIcon.fromTheme(app.icon)
                if not icon.isNull():
                    name_item.setIcon(icon)
            if app.is_essential:
                name_item.setForeground(QColor(_CLR_ESSENTIAL))
                name_item.setToolTip("⛔ Essential system package – removal blocked")
            if app.description:
                name_item.setToolTip(
                    (name_item.toolTip() + "\n" if name_item.toolTip() else "")
                    + app.description
                )
            # Store the AppEntry reference for retrieval on selection
            name_item.setData(Qt.ItemDataRole.UserRole, row)
            self._table.setItem(row, _COL_NAME, name_item)

            # Package ID
            pkg_item = QTableWidgetItem(app.package_id)
            pkg_item.setForeground(QColor(_CLR_TEXT_DIM))
            self._table.setItem(row, _COL_PKG, pkg_item)

            # Source badge (the delegate paints the pill)
            src_label = {
                PackageSource.APT: "APT",
                PackageSource.SNAP: "Snap",
                PackageSource.FLATPAK: "Flatpak",
            }[app.source]
            src_item = QTableWidgetItem(src_label)
            src_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, _COL_SOURCE, src_item)

            # Version
            ver_item = QTableWidgetItem(app.version or "–")
            ver_item.setForeground(QColor(_CLR_TEXT_DIM))
            self._table.setItem(row, _COL_VER, ver_item)

            # Size
            size_item = QTableWidgetItem(app.installed_size or "–")
            size_item.setTextAlignment(
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            )
            self._table.setItem(row, _COL_SIZE, size_item)

            self._table.setRowHeight(row, 44)

        self._table.setSortingEnabled(True)

        # Keep a parallel list so we can map row → AppEntry later
        self._visible_apps = visible

    # ── Filtering ────────────────────────────────────────────────────

    @staticmethod
    def _matches_filter(app: AppEntry, tag: str, search: str) -> bool:
        if tag != "All":
            source_map = {
                "APT": PackageSource.APT,
                "Snap": PackageSource.SNAP,
                "Flatpak": PackageSource.FLATPAK,
            }
            if app.source != source_map.get(tag):
                return False
        if search:
            haystack = f"{app.name} {app.package_id} {app.description}".lower()
            if search not in haystack:
                return False
        return True

    def _set_filter(self, label: str) -> None:
        self._active_filter = label
        self._refresh_tags()
        self._apply_filters()

    def _apply_filters(self) -> None:
        self._populate_table()

    def _refresh_tags(self) -> None:
        for label, btn in self._tag_buttons.items():
            btn.setStyleSheet(_tag_style(label == self._active_filter))

    def _source_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for app in self._apps:
            counts[app.source.name] = counts.get(app.source.name, 0) + 1
        return counts

    # ── Selection ────────────────────────────────────────────────────

    def _on_selection_changed(self) -> None:
        selected = self._get_selected_apps()
        removable = [a for a in selected if a.is_removable]
        n = len(removable)
        self._selected_count_label.setText(
            f"{n} removable selected" if n else "0 selected"
        )
        self._btn_purge.setEnabled(n > 0)

    def _get_selected_apps(self) -> list[AppEntry]:
        """Return the AppEntry objects for the currently selected rows."""
        rows = {idx.row() for idx in self._table.selectedIndexes()}
        result: list[AppEntry] = []
        for row in sorted(rows):
            if 0 <= row < len(self._visible_apps):
                result.append(self._visible_apps[row])
        return result

    # ── Purge action ─────────────────────────────────────────────────

    def _on_purge_clicked(self) -> None:
        selected = self._get_selected_apps()
        removable = [a for a in selected if a.is_removable]
        if not removable:
            return

        # Import here to avoid circular imports at module level
        from ui.confirm_modal import ConfirmModal

        modal = ConfirmModal(removable, parent=self)
        if modal.exec():
            self.purge_requested.emit(removable)
            # Refresh the list after purge
            self._start_scan()

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _make_font(size: int, bold: bool = False) -> QFont:
        font = QFont()
        font.setPointSize(size)
        if bold:
            font.setBold(True)
        return font

    @staticmethod
    def _action_btn_style(secondary: bool = False) -> str:
        if secondary:
            return (
                f"QPushButton {{"
                f"  background-color: {_CLR_SURFACE}; color: {_CLR_TEXT};"
                f"  border: 1px solid {_CLR_BORDER}; border-radius: 8px;"
                f"  padding: 0 20px; font-size: 13px; font-weight: 600;"
                f"}}"
                f"QPushButton:hover {{ background-color: {_CLR_SURFACE_ALT}; }}"
                f"QPushButton:disabled {{ color: {_CLR_TEXT_DIM}; }}"
            )
        return (
            f"QPushButton {{"
            f"  background-color: {_CLR_ACCENT}; color: {_CLR_TEXT};"
            f"  border: none; border-radius: 8px;"
            f"  padding: 0 24px; font-size: 13px; font-weight: 700;"
            f"}}"
            f"QPushButton:hover {{ background-color: {_CLR_ACCENT_HOVER}; }}"
            f"QPushButton:disabled {{ background-color: {_CLR_TAG_INACTIVE}; color: {_CLR_TEXT_DIM}; }}"
        )
