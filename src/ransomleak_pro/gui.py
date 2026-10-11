"""PySide6 desktop interface for RansomLeak Pro."""
from __future__ import annotations

import threading
import traceback
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from .archives import PY7ZR_AVAILABLE, RAR_AVAILABLE
from .config import APP_NAME, APP_TITLE, APP_VERSION
from .models import ScanCounters, ScanOptions, ScanResult
from .reporting import write_forensic_report
from .scanner import ForensicScanner
from .utils import format_eta, format_size, normalize_domain, safe_filename


class ScanSignals(QObject):
    log = Signal(str, str)
    progress = Signal(str)
    stats = Signal(object)
    finished = Signal(object)
    error = Signal(str)


class ScanTask(QRunnable):
    def __init__(self, options: ScanOptions, cancel_event: threading.Event) -> None:
        super().__init__()
        self.options = options
        self.cancel_event = cancel_event
        self.signals = ScanSignals()

    def run(self) -> None:
        try:
            scanner = ForensicScanner(
                cancel_event=self.cancel_event,
                log_callback=self.signals.log.emit,
                progress_callback=self.signals.progress.emit,
                stats_callback=self.signals.stats.emit,
            )
            self.signals.finished.emit(scanner.scan(self.options))
        except Exception as exc:
            detail = f"{type(exc).__name__}: {exc}"
            self.signals.log.emit(detail, "error")
            self.signals.log.emit(traceback.format_exc(limit=6), "error")
            self.signals.error.emit(detail)


class ReportSignals(QObject):
    progress = Signal(int, int)
    finished = Signal(str, str)
    error = Signal(str)


class ReportTask(QRunnable):
    def __init__(self, output: Path, result: ScanResult, options: ScanOptions) -> None:
        super().__init__()
        self.output = output
        self.result = result
        self.options = options
        self.signals = ReportSignals()

    def run(self) -> None:
        try:
            digest = write_forensic_report(
                self.output,
                self.result,
                self.options,
                progress_callback=self.signals.progress.emit,
            )
            self.signals.finished.emit(str(self.output), digest)
        except Exception as exc:
            self.signals.error.emit(f"{type(exc).__name__}: {exc}")


class StatCard(QFrame):
    def __init__(self, title: str) -> None:
        super().__init__()
        self.setObjectName("statCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        self.value = QLabel("0")
        self.value.setObjectName("statValue")
        label = QLabel(title)
        label.setObjectName("statLabel")
        layout.addWidget(self.value)
        layout.addWidget(label)


class RansomLeakWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1380, 860)
        self.setMinimumSize(1120, 720)
        self.thread_pool = QThreadPool.globalInstance()
        self.cancel_event = threading.Event()
        self.is_scanning = False
        self.is_saving = False
        self.last_result: ScanResult | None = None
        self.last_options: ScanOptions | None = None
        self._build_ui()
        self._apply_styles()
        self._set_dependency_status()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel(APP_NAME.upper())
        title.setObjectName("title")
        subtitle = QLabel(f"v{APP_VERSION}  •  Deep Forensic Archive Inventory  •  Read-Only Engine")
        subtitle.setObjectName("subtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box)
        header.addStretch()
        self.header_status = QLabel("READY")
        self.header_status.setObjectName("headerStatus")
        header.addWidget(self.header_status)
        root.addLayout(header)

        body = QHBoxLayout()
        body.setSpacing(14)
        root.addLayout(body, 1)

        left = QFrame()
        left.setObjectName("panel")
        left.setFixedWidth(365)
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(16, 16, 16, 16)
        left_layout.setSpacing(10)
        body.addWidget(left)

        left_layout.addWidget(self._section_label("CASE METADATA"))
        self.victim_edit = QLineEdit("victim")
        self.victim_edit.setPlaceholderText("Victim / Case Name")
        left_layout.addWidget(self.victim_edit)
        self.domain_edit = QLineEdit("xxxxx")
        self.domain_edit.setPlaceholderText("Domain")
        left_layout.addWidget(self.domain_edit)

        left_layout.addSpacing(8)
        left_layout.addWidget(self._section_label("SOURCE DATASET"))
        folder_row = QHBoxLayout()
        self.folder_edit = QLineEdit()
        self.folder_edit.setReadOnly(True)
        self.folder_edit.setPlaceholderText("Select a local dataset directory")
        browse = QPushButton("Browse")
        browse.clicked.connect(self._browse_folder)
        self.browse_btn = browse
        folder_row.addWidget(self.folder_edit, 1)
        folder_row.addWidget(browse)
        left_layout.addLayout(folder_row)

        left_layout.addSpacing(8)
        left_layout.addWidget(self._section_label("SCAN OPTIONS"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["normal", "deep", "ultra"])
        self.mode_combo.setCurrentText("deep")
        left_layout.addWidget(self.mode_combo)
        self.aggressive_magic = QCheckBox("Aggressive magic-byte detection")
        self.verbose = QCheckBox("Verbose archive log")
        self.auto_save = QCheckBox("Prompt to save after scan")
        self.auto_save.setChecked(True)
        left_layout.addWidget(self.aggressive_magic)
        left_layout.addWidget(self.verbose)
        left_layout.addWidget(self.auto_save)

        self.dep_label = QLabel()
        self.dep_label.setObjectName("muted")
        self.dep_label.setWordWrap(True)
        left_layout.addWidget(self.dep_label)
        left_layout.addStretch()

        self.scan_btn = QPushButton("START DEEP SCAN")
        self.scan_btn.setObjectName("primaryButton")
        self.scan_btn.clicked.connect(self._start_scan)
        self.cancel_btn = QPushButton("Cancel Scan")
        self.cancel_btn.setObjectName("dangerButton")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_scan)
        self.save_btn = QPushButton("Save Report")
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self._save_report)
        self.clear_btn = QPushButton("Clear Log")
        self.clear_btn.clicked.connect(self._clear_log)
        left_layout.addWidget(self.scan_btn)
        left_layout.addWidget(self.cancel_btn)
        left_layout.addWidget(self.save_btn)
        left_layout.addWidget(self.clear_btn)

        right = QVBoxLayout()
        body.addLayout(right, 1)
        stat_grid = QGridLayout()
        stat_grid.setSpacing(10)
        self.rows_card = StatCard("REPORT ROWS")
        self.size_card = StatCard("ON-DISK SIZE")
        self.archives_card = StatCard("ARCHIVES")
        self.nested_card = StatCard("NESTED")
        self.issues_card = StatCard("ISSUES")
        for i, card in enumerate([
            self.rows_card, self.size_card, self.archives_card,
            self.nested_card, self.issues_card,
        ]):
            stat_grid.addWidget(card, 0, i)
        right.addLayout(stat_grid)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(5000)
        self.log.setObjectName("log")
        right.addWidget(self.log, 1)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        right.addWidget(self.progress)
        self.status = QLabel("Ready.")
        self.status.setObjectName("muted")
        self.status.setMinimumHeight(22)
        right.addWidget(self.status)

    def _section_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("sectionTitle")
        return label

    def _apply_styles(self) -> None:
        self.setStyleSheet("""
            QWidget { background: #0b0f14; color: #e8eef5; font-family: 'Segoe UI'; font-size: 10pt; }
            QFrame#panel, QFrame#statCard { background: #111821; border: 1px solid #1c2a38; border-radius: 12px; }
            QLabel#title { font-size: 24pt; font-weight: 700; }
            QLabel#subtitle, QLabel#muted, QLabel#statLabel { color: #8291a3; }
            QLabel#headerStatus { color: #4cc9f0; font-weight: 700; }
            QLabel#sectionTitle { font-weight: 700; font-size: 10pt; color: #dce7f2; }
            QLabel#statValue { color: #4cc9f0; font-size: 19pt; font-weight: 700; }
            QLineEdit, QComboBox, QPlainTextEdit { background: #0c131b; border: 1px solid #263547; border-radius: 8px; padding: 7px; }
            QPlainTextEdit#log { font-family: Consolas, 'Cascadia Mono', monospace; }
            QPushButton { background: #1b2633; border: 0; border-radius: 8px; padding: 9px 12px; font-weight: 600; }
            QPushButton:hover { background: #263547; }
            QPushButton:disabled { color: #66717d; background: #151b22; }
            QPushButton#primaryButton { background: #4cc9f0; color: #071018; }
            QPushButton#primaryButton:hover { background: #72d9f5; }
            QPushButton#dangerButton { background: #ff5c77; color: white; }
            QProgressBar { border: 0; background: #16202b; border-radius: 4px; height: 9px; text-align: center; }
            QProgressBar::chunk { background: #4cc9f0; border-radius: 4px; }
            QCheckBox { spacing: 8px; }
        """)

    def _set_dependency_status(self) -> None:
        self.dep_label.setText(
            "Built-in ZIP  •  "
            + ("RAR: READY" if RAR_AVAILABLE else "RAR: NOT INSTALLED")
            + "  •  "
            + ("7Z: READY" if PY7ZR_AVAILABLE else "7Z: NOT INSTALLED")
        )

    def _browse_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select Dataset Directory")
        if path:
            self.folder_edit.setText(path)
            self._append_log(f"Source directory selected: {path}", "info")

    def _start_scan(self) -> None:
        if self.is_scanning or self.is_saving:
            return
        folder = self.folder_edit.text().strip()
        if not folder:
            QMessageBox.warning(self, "No Source Selected", "Please select a dataset directory first.")
            return
        root = Path(folder)
        if not root.exists() or not root.is_dir():
            QMessageBox.critical(self, "Invalid Directory", "The selected directory is no longer valid.")
            return

        options = ScanOptions(
            root_path=root,
            deep_mode=self.mode_combo.currentText(),
            aggressive_magic=self.aggressive_magic.isChecked(),
            verbose=self.verbose.isChecked(),
            victim=self.victim_edit.text().strip() or "victim",
            domain=normalize_domain(self.domain_edit.text().strip() or "xxxxx"),
            started_at=datetime.now(),
            auto_save_prompt=self.auto_save.isChecked(),
        )
        self.last_options = options
        self.last_result = None
        self.cancel_event.clear()
        self.is_scanning = True
        self._set_running_state(True)
        self.log.clear()
        self._update_stats(ScanCounters())
        self.progress.setRange(0, 0)
        self.status.setText("Initializing deep forensic scan...")

        task = ScanTask(options, self.cancel_event)
        task.signals.log.connect(self._append_log)
        task.signals.progress.connect(self.status.setText)
        task.signals.stats.connect(self._update_stats)
        task.signals.finished.connect(self._scan_finished)
        task.signals.error.connect(self._scan_error)
        self.thread_pool.start(task)

    def _cancel_scan(self) -> None:
        if not self.is_scanning:
            return
        self.cancel_event.set()
        self.cancel_btn.setEnabled(False)
        self.status.setText("Cancellation requested. Waiting for the current safe operation to finish...")
        self._append_log("Cancellation request received.", "warning")

    def _scan_finished(self, result: ScanResult) -> None:
        self.is_scanning = False
        self.last_result = result
        self._set_running_state(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self._update_stats(result.counters)
        if result.cancelled:
            self.status.setText("Scan cancelled. Partial forensic report is available.")
            QMessageBox.warning(
                self,
                APP_TITLE,
                f"The scan was cancelled.\n\nReport rows: {result.counters.report_rows:,}\n"
                f"On-disk size: {format_size(result.counters.total_size_bytes)}\n\n"
                "The partial report can still be saved.",
            )
        else:
            self.status.setText("Deep forensic inventory completed successfully.")
            c = result.counters
            QMessageBox.information(
                self,
                "Scan Completed",
                "Deep forensic inventory completed.\n\n"
                f"Report rows: {c.report_rows:,}\n"
                f"Filesystem files: {c.filesystem_files:,}\n"
                f"On-disk size: {format_size(c.total_size_bytes)}\n"
                f"Archives: {c.archives_found:,}\n"
                f"Nested archives: {c.nested_archives_found:,}\n"
                f"Broken archives: {c.archives_broken:,}\n"
                f"Warnings: {c.warnings:,}\n"
                f"Elapsed: {format_eta(result.elapsed_seconds)}",
            )
        self.save_btn.setEnabled(bool(result.entries))
        if self.last_options and self.last_options.auto_save_prompt and result.entries:
            self._save_report()

    def _scan_error(self, message: str) -> None:
        self.is_scanning = False
        self._set_running_state(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.status.setText("Scan terminated with a critical error.")
        QMessageBox.critical(self, "Scan Error", message)

    def _save_report(self) -> None:
        if self.is_scanning or self.is_saving or not self.last_result or not self.last_options:
            return
        victim_filename = safe_filename(self.last_options.victim).lower()
        default = str(self.last_options.root_path.parent / f"forensic_inventory_{victim_filename}.txt")
        output, _ = QFileDialog.getSaveFileName(
            self,
            "Save Forensic Inventory",
            default,
            "Forensic TXT Report (*.txt);;All Files (*.*)",
        )
        if not output:
            return
        self.is_saving = True
        self._set_saving_state(True)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.status.setText("Preparing atomic forensic report...")
        task = ReportTask(Path(output), self.last_result, self.last_options)
        task.signals.progress.connect(self._report_progress)
        task.signals.finished.connect(self._report_finished)
        task.signals.error.connect(self._report_error)
        self.thread_pool.start(task)

    def _report_progress(self, index: int, total: int) -> None:
        percent = 100 if total <= 0 else int(index * 100 / total)
        self.progress.setValue(percent)
        self.status.setText(f"Writing forensic report... {index:,}/{total:,}")

    def _report_finished(self, output: str, digest: str) -> None:
        self.is_saving = False
        self._set_saving_state(False)
        self.progress.setValue(100)
        self.status.setText(f"Report saved successfully: {output}")
        self._append_log(f"Forensic report saved atomically: {output}", "success")
        self._append_log(f"Data lines SHA-256: {digest}", "success")
        QMessageBox.information(self, "Report Saved", f"The forensic inventory report was saved successfully.\n\n{output}")

    def _report_error(self, message: str) -> None:
        self.is_saving = False
        self._set_saving_state(False)
        self.status.setText("Report save failed.")
        self._append_log(f"Report save error: {message}", "error")
        QMessageBox.critical(self, "Report Save Error", message)

    def _set_running_state(self, running: bool) -> None:
        self.scan_btn.setEnabled(not running)
        self.scan_btn.setText("SCANNING..." if running else "START DEEP SCAN")
        self.cancel_btn.setEnabled(running)
        self.browse_btn.setEnabled(not running)
        self.clear_btn.setEnabled(not running)
        self.save_btn.setEnabled(not running and bool(self.last_result and self.last_result.entries))
        self.header_status.setText("SCANNING" if running else "READY")

    def _set_saving_state(self, saving: bool) -> None:
        self.scan_btn.setEnabled(not saving)
        self.browse_btn.setEnabled(not saving)
        self.clear_btn.setEnabled(not saving)
        self.save_btn.setEnabled(not saving and bool(self.last_result and self.last_result.entries))
        self.header_status.setText("SAVING" if saving else "READY")

    def _append_log(self, message: str, level: str = "info") -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "error": "ERROR",
            "warning": "WARN",
            "success": "OK",
            "archive": "ARCHIVE",
            "nested": "NESTED",
        }.get(level, "INFO")
        self.log.appendPlainText(f"[{stamp}] [{prefix}] {message}")

    def _update_stats(self, counters: ScanCounters) -> None:
        self.rows_card.value.setText(f"{counters.report_rows:,}")
        self.size_card.value.setText(format_size(counters.total_size_bytes))
        self.archives_card.value.setText(f"{counters.archives_found:,}")
        self.nested_card.value.setText(f"{counters.nested_archives_found:,}")
        self.issues_card.value.setText(f"{counters.archives_broken + counters.warnings:,}")

    def _clear_log(self) -> None:
        if not self.is_scanning and not self.is_saving:
            self.log.clear()

    def closeEvent(self, event) -> None:
        if self.is_saving:
            QMessageBox.warning(self, "Report Save In Progress", "Please wait until the save operation finishes.")
            event.ignore()
            return
        if self.is_scanning:
            answer = QMessageBox.question(
                self,
                "Scan In Progress",
                "A scan is still running. Closing will request cancellation. Exit anyway?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                event.ignore()
                return
            self.cancel_event.set()
        event.accept()


def apply_dark_palette(app: QApplication) -> None:
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor("#0b0f14"))
    palette.setColor(QPalette.WindowText, QColor("#e8eef5"))
    palette.setColor(QPalette.Base, QColor("#0c131b"))
    palette.setColor(QPalette.AlternateBase, QColor("#111821"))
    palette.setColor(QPalette.Text, QColor("#e8eef5"))
    palette.setColor(QPalette.Button, QColor("#1b2633"))
    palette.setColor(QPalette.ButtonText, QColor("#e8eef5"))
    palette.setColor(QPalette.Highlight, QColor("#4cc9f0"))
    palette.setColor(QPalette.HighlightedText, QColor("#071018"))
    app.setPalette(palette)
