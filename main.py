"""
PurePurge – Main Entry Point
=============================
Wires the Dashboard UI to the scanner and purger backends.

Architecture
------------
::

    ┌──────────┐  scan_all()   ┌──────────┐
    │ Scanner  │──────────────▶│Dashboard │
    └──────────┘               │  (UI)    │
                               │          │  purge_requested(apps)
    ┌──────────┐  purge_*()    │          │─────────────────────────┐
    │ Purger   │◀──────────────│          │                         │
    └──────────┘  PurgeResult  └──────────┘                         ▼
                                                          ┌────────────────┐
                                                          │ _PurgeWorker   │
                                                          │ (QThread)      │
                                                          └──────┬─────────┘
                                                                 │ finished(results)
                                                                 ▼
                                                          ┌────────────────┐
                                                          │ _ResultDialog  │
                                                          └────────────────┘

Flow:
  1. Dashboard launches a background scan (:func:`scan_all`) on startup.
  2. User searches / filters / selects apps → clicks **Purge Selected**.
  3. :class:`~ui.confirm_modal.ConfirmModal` shows an inspection preview.
  4. On confirmation, ``purge_requested`` fires → ``main`` dispatches to
     a :class:`_PurgeWorker` (QThread) so the UI stays responsive.
  5. A :class:`_ResultDialog` shows the outcome, then the dashboard
     rescans to reflect the new state.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass, field

from PyQt6.QtCore import QThread, Qt, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QColor, QFont, QIcon
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressDialog,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.purger import PurgeResult, purge_apt, purge_flatpak, purge_snap
from core.scanner import AppEntry, PackageSource
from ui.dashboard import Dashboard

log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Aggregate result container
# ──────────────────────────────────────────────────────────────────────

@dataclass
class _AggregateResult:
    apt: PurgeResult | None = None
    snap: PurgeResult | None = None
    flatpak: PurgeResult | None = None

    @property
    def all_results(self) -> list[tuple[str, PurgeResult]]:
        out: list[tuple[str, PurgeResult]] = []
        if self.apt:
            out.append(("APT", self.apt))
        if self.snap:
            out.append(("Snap", self.snap))
        if self.flatpak:
            out.append(("Flatpak", self.flatpak))
        return out

    @property
    def success(self) -> bool:
        return all(r.success for _, r in self.all_results)


# ──────────────────────────────────────────────────────────────────────
# Background purge worker
# ──────────────────────────────────────────────────────────────────────

class _PurgeWorker(QThread):
    """Runs purge operations off the main thread."""

    finished = pyqtSignal(object)  # _AggregateResult
    progress = pyqtSignal(str)     # status message

    def __init__(self, apps: list[AppEntry], parent=None) -> None:
        super().__init__(parent)
        self._apps = apps

    def run(self) -> None:
        result = _AggregateResult()

        apt_pkgs = [a.package_id for a in self._apps if a.source == PackageSource.APT]
        snaps    = [a.package_id for a in self._apps if a.source == PackageSource.SNAP]
        flatpaks = [a.package_id for a in self._apps if a.source == PackageSource.FLATPAK]

        if apt_pkgs:
            self.progress.emit(f"Purging {len(apt_pkgs)} APT package(s)…")
            result.apt = purge_apt(apt_pkgs)
            log.info("APT purge: %s", result.apt.summary)

        if snaps:
            self.progress.emit(f"Purging {len(snaps)} Snap package(s)…")
            result.snap = purge_snap(snaps)
            log.info("Snap purge: %s", result.snap.summary)

        if flatpaks:
            self.progress.emit(f"Purging {len(flatpaks)} Flatpak app(s)…")
            result.flatpak = purge_flatpak(flatpaks)
            log.info("Flatpak purge: %s", result.flatpak.summary)

        self.finished.emit(result)


# ──────────────────────────────────────────────────────────────────────
# Result dialog
# ──────────────────────────────────────────────────────────────────────

_CLR_BG      = "#1a1a2e"
_CLR_SURFACE = "#16213e"
_CLR_TEXT    = "#eaeaea"
_CLR_DIM     = "#8892a8"
_CLR_BORDER  = "#2a2a4a"
_CLR_GREEN   = "#10ac84"
_CLR_RED     = "#e94560"


class _ResultDialog(QDialog):
    """Shows the outcome of a purge operation."""

    def __init__(self, result: _AggregateResult, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Purge Complete" if result.success else "Purge Finished with Errors")
        self.setMinimumSize(560, 380)
        self.setModal(True)
        self.setStyleSheet(f"""
            QDialog {{ background-color: {_CLR_BG}; }}
            QLabel  {{ color: {_CLR_TEXT}; }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(14)

        # Header
        icon_text = "✔" if result.success else "⚠"
        colour    = _CLR_GREEN if result.success else _CLR_RED
        headline  = "All operations completed successfully." if result.success else "Some operations encountered errors."

        hdr = QLabel(f'<span style="font-size:28px; color:{colour};">{icon_text}</span>'
                     f'&nbsp;&nbsp;<span style="font-size:15px;">{headline}</span>')
        hdr.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(hdr)

        # Detail log
        detail = QTextEdit()
        detail.setReadOnly(True)
        detail.setStyleSheet(
            f"background-color: {_CLR_SURFACE}; color: {_CLR_TEXT}; "
            f"border: 1px solid {_CLR_BORDER}; border-radius: 6px; "
            f"font-family: monospace; font-size: 12px; padding: 8px;"
        )

        lines: list[str] = []
        for label, r in result.all_results:
            status = "✔ SUCCESS" if r.success else "✘ FAILED"
            lines.append(f"── {label} ({status}) ──")
            if r.blocked_packages:
                lines.append(f"  Blocked (essential): {', '.join(r.blocked_packages)}")
            if r.commands_run:
                lines.append(f"  Commands executed: {len(r.commands_run)}")
            if r.stdout.strip():
                for out_line in r.stdout.strip().splitlines()[:20]:
                    lines.append(f"  │ {out_line}")
            if r.stderr.strip():
                lines.append("  STDERR:")
                for err_line in r.stderr.strip().splitlines()[:20]:
                    lines.append(f"  │ {err_line}")
            lines.append("")

        detail.setPlainText("\n".join(lines))
        layout.addWidget(detail, stretch=1)

        # Close button
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_close = QPushButton("Close")
        btn_close.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_close.setFixedHeight(36)
        btn_close.setStyleSheet(
            f"QPushButton {{ background-color: {_CLR_GREEN}; color: {_CLR_TEXT}; "
            f"border: none; border-radius: 8px; padding: 0 24px; "
            f"font-size: 13px; font-weight: 700; }}"
            f"QPushButton:hover {{ background-color: #1dd1a1; }}"
        )
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)
        layout.addLayout(btn_row)


# ──────────────────────────────────────────────────────────────────────
# Application controller
# ──────────────────────────────────────────────────────────────────────

class PurePurgeApp(QWidget):
    """Top-level controller that owns the QApplication, Dashboard, and
    coordinates purge operations via background workers.

    Inherits :class:`QWidget` so that its methods qualify as valid pyqtSlot
    receivers for Qt signal connections.
    """

    def __init__(self, argv: list[str] | None = None) -> None:
        self._qapp = QApplication(argv or sys.argv)
        super().__init__()  # QWidget.__init__ — must come after QApplication

        self._qapp.setApplicationName("PurePurge")
        self._qapp.setDesktopFileName("purepurge")
        self._qapp.setApplicationVersion("1.0.0")

        self._dashboard = Dashboard()
        self._dashboard.purge_requested.connect(self._on_purge_requested)

        self._worker: _PurgeWorker | None = None
        self._progress_dlg: QProgressDialog | None = None

    def run(self) -> int:
        """Show the dashboard and enter the event loop."""
        self._dashboard.show()
        return self._qapp.exec()

    # ── Purge dispatch ───────────────────────────────────────────────

    @pyqtSlot(list)
    def _on_purge_requested(self, apps: list[AppEntry]) -> None:
        """Spawn a background worker that runs the actual purge."""
        if self._worker is not None and self._worker.isRunning():
            QMessageBox.warning(
                self._dashboard,
                "Purge in progress",
                "Another purge operation is already running. Please wait.",
            )
            return

        # Progress dialog (indeterminate)
        self._progress_dlg = QProgressDialog(
            "Preparing purge…", None, 0, 0, self._dashboard
        )
        self._progress_dlg.setWindowTitle("PurePurge")
        self._progress_dlg.setWindowModality(Qt.WindowModality.WindowModal)
        self._progress_dlg.setMinimumWidth(380)
        self._progress_dlg.setCancelButton(None)  # cannot cancel mid-purge
        self._progress_dlg.setStyleSheet(
            f"QProgressDialog {{ background-color: {_CLR_BG}; }}"
            f"QLabel {{ color: {_CLR_TEXT}; font-size: 13px; }}"
            f"QProgressBar {{ background-color: {_CLR_SURFACE}; border: none; "
            f"border-radius: 4px; text-align: center; color: {_CLR_TEXT}; }}"
            f"QProgressBar::chunk {{ background-color: {_CLR_RED}; border-radius: 4px; }}"
        )
        self._progress_dlg.show()

        self._worker = _PurgeWorker(apps, parent=None)
        self._worker.progress.connect(self._on_purge_progress)
        self._worker.finished.connect(self._on_purge_finished)
        self._worker.start()

    @pyqtSlot(str)
    def _on_purge_progress(self, message: str) -> None:
        if self._progress_dlg:
            self._progress_dlg.setLabelText(message)

    @pyqtSlot(object)
    def _on_purge_finished(self, result: _AggregateResult) -> None:
        if self._progress_dlg:
            self._progress_dlg.close()
            self._progress_dlg = None

        dlg = _ResultDialog(result, parent=self._dashboard)
        dlg.exec()

        # Rescan to reflect the new state of installed packages
        self._dashboard._start_scan()


# ──────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    app = PurePurgeApp(sys.argv)
    sys.exit(app.run())


if __name__ == "__main__":
    main()
