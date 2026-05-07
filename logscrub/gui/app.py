"""
PySide6 GUI for LogScrub — v2.0

Features:
- Policy profile selector (GDPR, HIPAA, SOC2, Minimal, user-defined)
- Editor with inline diff highlighting of masked spans
- Findings table with confidence column and right-click allowlist
- Allowlist manager
- Custom pattern editor with ReDoS-safe regex tester
- Batch scrub panel
- Export / Report dialog (masked output, audit log JSON/CSV, report viewer)
"""

from __future__ import annotations

import json
import multiprocessing
import re
import sys
import threading
from pathlib import Path
from typing import Sequence

from PySide6.QtCore import Qt, QTimer, QObject, QSettings, Signal
from PySide6.QtGui import (
    QColor, QDragEnterEvent, QDropEvent, QFont,
    QTextCharFormat, QKeySequence, QShortcut,
)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QDialog,
    QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QTextEdit,
    QPushButton, QRadioButton, QCheckBox, QComboBox,
    QTabWidget, QTreeWidget, QTreeWidgetItem,
    QScrollArea, QFrame, QListWidget,
    QStatusBar, QButtonGroup, QHeaderView,
    QAbstractItemView, QFileDialog, QMessageBox, QMenu,
    QSizePolicy, QSlider, QProgressBar,
)

from ..engine import scrub, ScrubResult
from ..handlers import scrub_json, scrub_csv
from ..patterns import Pattern
from ..audit import export_json as audit_json, export_csv as audit_csv, export_text
from ..profiles import list_profiles, save_profile, get_profile, Profile


def _regex_test_mp_worker(
    pattern_str: str, sample: str, result_queue: "multiprocessing.Queue[object]"
) -> None:
    """Run re.findall in a subprocess so the caller can terminate() on timeout."""
    import re as _re
    try:
        result_queue.put(_re.compile(pattern_str).findall(sample))
    except Exception as exc:
        result_queue.put(exc)


# ── Constants ──────────────────────────────────────────────────────────────────

_VERSION = "2.0.0"

# Files larger than this are truncated in the editor display (scrub still runs on full text)
_LARGE_FILE_DISPLAY_CHARS = 256 * 1024  # 256 KB

_MASK_STYLES = [
    ("partial",  "Partial  (a***@b.com)"),
    ("label",    "Type label  ([EMAIL])"),
    ("full",     "Full block  (*****)"),
    ("redacted", "Redacted  ([REDACTED])"),
    ("token",    "Token  ([PII-001])"),
]

_MASK_PRESETS = [("*", "*"), ("\u2588", "\u2588"), ("X", "X"), ("#", "#")]

_PATTERN_GROUPS: list[tuple[str, list[tuple[str, str]]]] = [
    ("PII", [
        ("email",       "Email"),
        ("ssn",         "SSN"),
        ("phone",       "Phone"),
        ("us_passport", "US Passport"),
    ]),
    ("Credentials", [
        ("jwt",                "JWT"),
        ("bearer_token",       "Bearer token"),
        ("openai_key",         "OpenAI key"),
        ("github_token",       "GitHub token"),
        ("aws_access_key",     "AWS key"),
        ("generic_credential", "Generic credential"),
        ("slack_token",        "Slack token"),
        ("stripe_key",         "Stripe key"),
        ("google_api_key",     "Google API key"),
        ("anthropic_key",      "Anthropic key"),
        ("sendgrid_key",       "SendGrid key"),
    ]),
    ("Financial", [
        ("iban",        "IBAN"),
        ("credit_card", "Credit card"),
    ]),
    ("Network", [
        ("url_credentials", "URL credentials"),
        ("ipv4",            "IPv4 address"),
        ("mac_address",     "MAC address"),
    ]),
]

# ── Dark stylesheet ────────────────────────────────────────────────────────────

_DARK_QSS = """
QMainWindow, QDialog {
    background-color: #1e1e1e;
    color: #d4d4d4;
}
QWidget {
    background-color: #1e1e1e;
    color: #d4d4d4;
    font-family: "Segoe UI", "SF Pro Display", "Helvetica Neue", Arial, sans-serif;
    font-size: 13px;
}
QScrollArea, QScrollArea > QWidget > QWidget {
    background-color: transparent;
    border: none;
}
QFrame#sidebar {
    background-color: #252526;
    border-right: 1px solid #3c3c3c;
}
QTextEdit, QPlainTextEdit {
    background-color: #252526;
    color: #d4d4d4;
    border: 1px solid #3c3c3c;
    border-radius: 4px;
    selection-background-color: #264f78;
}
QPushButton {
    background-color: #0e639c;
    color: white;
    border: none;
    border-radius: 4px;
    padding: 5px 14px;
    font-size: 13px;
}
QPushButton:hover { background-color: #1177bb; }
QPushButton:pressed { background-color: #0a4f7e; }
QPushButton:disabled { background-color: #3c3c3c; color: #6e6e6e; }
QComboBox {
    background-color: #3c3c3c;
    color: #d4d4d4;
    border: 1px solid #555555;
    border-radius: 4px;
    padding: 3px 8px;
    min-height: 24px;
}
QComboBox::drop-down { border: none; width: 20px; }
QComboBox QAbstractItemView {
    background-color: #2d2d2d;
    color: #d4d4d4;
    selection-background-color: #0e639c;
    border: 1px solid #555555;
}
QLineEdit {
    background-color: #3c3c3c;
    color: #d4d4d4;
    border: 1px solid #555555;
    border-radius: 4px;
    padding: 3px 8px;
    min-height: 24px;
}
QLineEdit:focus { border: 1px solid #0e639c; }
QRadioButton, QCheckBox { color: #d4d4d4; spacing: 6px; }
QRadioButton::indicator {
    width: 15px; height: 15px;
    border-radius: 8px;
    border: 2px solid #666666;
    background-color: #2d2d2d;
}
QRadioButton::indicator:hover { border-color: #999999; }
QRadioButton::indicator:checked {
    border: 2px solid #0e639c;
    background-color: #0e639c;
}
QCheckBox::indicator { width: 14px; height: 14px; }
QTabWidget::pane {
    border: 1px solid #3c3c3c;
    border-radius: 4px;
    background-color: #252526;
}
QTabBar::tab {
    background-color: #2d2d2d;
    color: #8c8c8c;
    border: none;
    padding: 6px 20px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: #252526;
    color: #d4d4d4;
    border-bottom: 2px solid #0e639c;
}
QTabBar::tab:hover:!selected { background-color: #3c3c3c; color: #d4d4d4; }
QTreeWidget {
    background-color: #252526;
    color: #d4d4d4;
    border: 1px solid #3c3c3c;
    alternate-background-color: #2d2d2d;
}
QTreeWidget::item:selected { background-color: #1f6aa5; color: white; }
QHeaderView::section {
    background-color: #1e1e1e;
    color: #888888;
    border: none;
    border-right: 1px solid #3c3c3c;
    padding: 4px 8px;
    font-size: 11px;
    font-weight: bold;
}
QListWidget {
    background-color: #252526;
    color: #d4d4d4;
    border: 1px solid #3c3c3c;
    border-radius: 4px;
}
QListWidget::item:selected { background-color: #1f6aa5; color: white; }
QMenu {
    background-color: #2d2d2d;
    color: #d4d4d4;
    border: 1px solid #555555;
}
QMenu::item:selected { background-color: #0e639c; }
QScrollBar:vertical {
    background: #1e1e1e; width: 10px; margin: 0;
}
QScrollBar::handle:vertical {
    background: #555555; min-height: 20px; border-radius: 5px;
}
QScrollBar::handle:vertical:hover { background: #777777; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal {
    background: #1e1e1e; height: 10px; margin: 0;
}
QScrollBar::handle:horizontal {
    background: #555555; min-width: 20px; border-radius: 5px;
}
QScrollBar::handle:horizontal:hover { background: #777777; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QStatusBar {
    background-color: #1a1a1a;
    color: #555555;
    border-top: 1px solid #2d2d2d;
    font-size: 11px;
}
QStatusBar::item { border: none; }
"""

def _mono_font() -> QFont:
    f = QFont()
    f.setFamilies(["Cascadia Code", "JetBrains Mono", "Consolas", "monospace"])
    f.setPointSize(12)
    return f


# ── Thread bridge ──────────────────────────────────────────────────────────────


class _Bridge(QObject):
    """Routes results from worker threads back to the main thread via Qt signals."""
    scrub_done = Signal(object, str, str, int, dict)
    # (result, input_text, file_format, gen, token_map)
    batch_log = Signal(str)
    batch_progress = Signal(int, int)  # (done, total)
    batch_done = Signal()


# ── Main window ────────────────────────────────────────────────────────────────


class LogScrubApp(QMainWindow):
    """Main application window."""

    def __init__(self, extra_patterns: Sequence[Pattern] = ()) -> None:
        super().__init__()
        self._extra_patterns: list[Pattern] = list(extra_patterns)
        self._custom_patterns: list[Pattern] = []
        self._last_result: ScrubResult | None = None
        self._file_format: str = "text"
        self._current_file: str = ""
        self._full_text: str = ""  # always the full file (may differ from display if truncated)
        self._min_confidence: float = 0.0
        self._scrub_timer = QTimer(self)
        self._scrub_timer.setSingleShot(True)
        self._scrub_timer.timeout.connect(self._scrub)
        self._scrub_gen: int = 0
        self._allowlist: set[str] = set()
        self._token_map: dict[str, str] = {}

        self._bridge = _Bridge()
        self._bridge.scrub_done.connect(self._apply_scrub_result)
        self._bridge.batch_log.connect(self._batch_log_line)
        self._bridge.batch_progress.connect(self._on_batch_progress)
        self._bridge.batch_done.connect(self._on_batch_done)

        self.setWindowTitle("LogScrub")
        self.resize(1260, 820)
        self.setMinimumSize(960, 640)
        self.setAcceptDrops(True)
        self._build_ui()
        self._bind_keys()
        self._load_settings()

    # ── Layout ─────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        sidebar = self._build_sidebar()
        sidebar.setFixedWidth(280)
        root.addWidget(sidebar)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(8, 8, 8, 4)
        right_layout.setSpacing(0)
        right_layout.addWidget(self._build_tabs())
        root.addWidget(right, stretch=1)

        self._build_statusbar()

    # ── Sidebar ────────────────────────────────────────────────────────────────

    def _build_sidebar(self) -> QFrame:
        outer = QFrame()
        outer.setObjectName("sidebar")
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        title = QLabel("LogScrub")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(
            "font-size: 18px; font-weight: bold; color: #d4d4d4;"
            "padding: 14px 0 8px 0; background: #252526;"
        )
        outer_layout.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background: #252526;")

        content = QWidget()
        content.setStyleSheet("background: #252526;")
        self._sl = QVBoxLayout(content)
        self._sl.setContentsMargins(0, 0, 0, 16)
        self._sl.setSpacing(0)
        self._sl.setAlignment(Qt.AlignTop)
        self._build_sidebar_content()
        scroll.setWidget(content)
        outer_layout.addWidget(scroll, stretch=1)
        return outer

    def _sec_lbl(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(
            "color: #888888; font-size: 10px; font-weight: bold;"
            "padding: 14px 16px 4px 16px; background: #252526;"
        )
        return lbl

    def _action_btn(self, text: str, primary: bool = False, danger: bool = False) -> QPushButton:
        if primary:
            bg, hover = "#0e639c", "#1177bb"
        elif danger:
            bg, hover = "#5a1a1a", "#6e2020"
        else:
            bg, hover = "#3c3c3c", "#4a4a4a"
        btn = QPushButton(text)
        btn.setFixedWidth(228)
        btn.setFixedHeight(34)
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {bg}; color: #d4d4d4;
                border: none; border-radius: 4px;
                font-size: 13px; text-align: left; padding-left: 10px;
            }}
            QPushButton:hover {{ background-color: {hover}; }}
        """)
        return btn

    def _build_sidebar_content(self) -> None:
        sl = self._sl

        # ── PROFILE ───────────────────────────────────────────────────────────
        sl.addWidget(self._sec_lbl("PROFILE"))
        pr_row = QWidget()
        pr_row.setStyleSheet("background: #252526;")
        pr_layout = QHBoxLayout(pr_row)
        pr_layout.setContentsMargins(12, 2, 12, 2)
        pr_layout.setSpacing(4)
        self._profile_combo = QComboBox()
        self._profile_combo.addItem("(none)")
        self._profile_combo.addItems([p.name for p in list_profiles()])
        self._profile_combo.currentTextChanged.connect(self._on_profile_select)
        pr_layout.addWidget(self._profile_combo, stretch=1)
        save_btn = QPushButton("Save\u2026")
        save_btn.setFixedSize(72, 28)
        save_btn.setStyleSheet(
            "background: #3c3c3c; color: #d4d4d4; border: none; border-radius: 4px; font-size: 11px;")
        save_btn.clicked.connect(self._save_profile_dialog)
        pr_layout.addWidget(save_btn)
        sl.addWidget(pr_row)

        pr_io_row = QWidget()
        pr_io_row.setStyleSheet("background: #252526;")
        pr_io_layout = QHBoxLayout(pr_io_row)
        pr_io_layout.setContentsMargins(12, 0, 12, 4)
        pr_io_layout.setSpacing(4)
        _io_style = "background: #3c3c3c; color: #d4d4d4; border: none; border-radius: 4px; font-size: 11px;"
        import_btn = QPushButton("Import\u2026")
        import_btn.setFixedHeight(24)
        import_btn.setStyleSheet(_io_style)
        import_btn.clicked.connect(self._import_profile)
        export_btn = QPushButton("Export\u2026")
        export_btn.setFixedHeight(24)
        export_btn.setStyleSheet(_io_style)
        export_btn.clicked.connect(self._export_profile)
        pr_io_layout.addWidget(import_btn, stretch=1)
        pr_io_layout.addWidget(export_btn, stretch=1)
        sl.addWidget(pr_io_row)

        # ── MASKING STYLE ─────────────────────────────────────────────────────
        sl.addWidget(self._sec_lbl("MASKING STYLE"))
        self._mask_style_group = QButtonGroup(self)
        for i, (value, label) in enumerate(_MASK_STYLES):
            rb = QRadioButton(label)
            rb.setProperty("mask_value", value)
            rb.setChecked(value == "partial")
            rb.setStyleSheet("padding: 2px 20px; background: #252526;")
            self._mask_style_group.addButton(rb, i)
            sl.addWidget(rb)
        self._mask_style_group.buttonClicked.connect(self._on_style_change)

        # ── MASK CHARACTER ────────────────────────────────────────────────────
        self._mask_char_header = self._sec_lbl("MASK CHARACTER")
        sl.addWidget(self._mask_char_header)

        preset_row = QWidget()
        preset_row.setStyleSheet("background: #252526;")
        preset_layout = QHBoxLayout(preset_row)
        preset_layout.setContentsMargins(16, 0, 16, 0)
        preset_layout.setSpacing(8)
        self._mask_char_group = QButtonGroup(self)
        for i, (label, value) in enumerate(_MASK_PRESETS):
            rb = QRadioButton(label)
            rb.setProperty("char_value", value)
            rb.setChecked(value == "*")
            rb.setStyleSheet("padding: 0; background: #252526;")
            self._mask_char_group.addButton(rb, i)
            preset_layout.addWidget(rb)
        preset_layout.addStretch()
        sl.addWidget(preset_row)

        custom_row = QWidget()
        custom_row.setStyleSheet("background: #252526;")
        custom_layout = QHBoxLayout(custom_row)
        custom_layout.setContentsMargins(16, 4, 16, 8)
        custom_layout.setSpacing(6)
        self._mask_char_custom_rb = QRadioButton("custom:")
        self._mask_char_custom_rb.setProperty("char_value", "__custom__")
        self._mask_char_custom_rb.setStyleSheet("padding: 0; background: #252526;")
        self._mask_char_group.addButton(self._mask_char_custom_rb, len(_MASK_PRESETS))
        custom_layout.addWidget(self._mask_char_custom_rb)
        self._custom_mask_entry = QLineEdit()
        self._custom_mask_entry.setFixedSize(40, 26)
        self._custom_mask_entry.setPlaceholderText("?")
        self._custom_mask_entry.textChanged.connect(self._on_setting_change)
        custom_layout.addWidget(self._custom_mask_entry)
        custom_layout.addStretch()
        sl.addWidget(custom_row)
        self._mask_char_group.buttonClicked.connect(self._on_setting_change)

        # ── PATTERNS ──────────────────────────────────────────────────────────
        sl.addWidget(self._sec_lbl("PATTERNS"))
        self._pattern_cbs: dict[str, QCheckBox] = {}

        for group_label, patterns in _PATTERN_GROUPS:
            hdr = QWidget()
            hdr.setStyleSheet("background: #252526;")
            hdr_layout = QHBoxLayout(hdr)
            hdr_layout.setContentsMargins(12, 8, 12, 2)
            hdr_layout.setSpacing(4)
            g_lbl = QLabel(group_label.upper())
            g_lbl.setStyleSheet("color: #555555; font-size: 10px; font-weight: bold; background: #252526;")
            hdr_layout.addWidget(g_lbl, stretch=1)
            for btn_text, enabled in [("All", True), ("None", False)]:
                b = QPushButton(btn_text)
                b.setFixedSize(34 if btn_text == "None" else 28, 18)
                b.setStyleSheet(
                    "background: #3c3c3c; color: #d4d4d4; border: none;"
                    "border-radius: 3px; font-size: 9px; padding: 0;")
                b.clicked.connect(lambda _checked, p=patterns, e=enabled: self._set_group(p, e))
                hdr_layout.addWidget(b)
            sl.addWidget(hdr)

            for name, label in patterns:
                cb = QCheckBox(label)
                cb.setChecked(True)
                cb.setStyleSheet("padding: 1px 24px; background: #252526;")
                cb.stateChanged.connect(self._on_setting_change)
                self._pattern_cbs[name] = cb
                sl.addWidget(cb)

        # ── CONFIDENCE THRESHOLD ──────────────────────────────────────────────
        sl.addWidget(self._sec_lbl("MIN CONFIDENCE"))
        conf_row = QWidget()
        conf_row.setStyleSheet("background: #252526;")
        conf_layout = QHBoxLayout(conf_row)
        conf_layout.setContentsMargins(16, 0, 16, 4)
        conf_layout.setSpacing(8)
        self._conf_slider = QSlider(Qt.Horizontal)
        self._conf_slider.setRange(0, 100)
        self._conf_slider.setValue(0)
        self._conf_slider.setStyleSheet(
            "QSlider::groove:horizontal { height:4px; background:#3c3c3c; border-radius:2px; }"
            "QSlider::handle:horizontal { width:14px; height:14px; margin:-5px 0;"
            " background:#0e639c; border-radius:7px; }"
            "QSlider::sub-page:horizontal { background:#0e639c; border-radius:2px; }")
        self._conf_label = QLabel("0%")
        self._conf_label.setFixedWidth(32)
        self._conf_label.setStyleSheet("color: #888888; font-size: 11px; background:#252526;")
        self._conf_slider.valueChanged.connect(self._on_confidence_change)
        conf_layout.addWidget(self._conf_slider, stretch=1)
        conf_layout.addWidget(self._conf_label)
        sl.addWidget(conf_row)

        # ── ACTIONS ───────────────────────────────────────────────────────────
        sl.addWidget(self._sec_lbl("ACTIONS"))
        for text, handler, primary, danger in [
            ("Open file\u2026  (Ctrl+O)", self._open_file, True,  False),
            ("Copy output",               self._copy,      False, False),
            ("Save output\u2026  (Ctrl+S)", self._save,    False, False),
            ("Export / Report\u2026",     self._show_export_dialog, False, False),
            ("Allowlist\u2026",           self._show_allowlist,     False, False),
            ("Custom patterns\u2026",     self._show_pattern_editor, False, False),
            ("Clear",                     self._clear,     False, True),
        ]:
            btn = self._action_btn(text, primary=primary, danger=danger)
            btn.clicked.connect(handler)
            row = QWidget()
            row.setStyleSheet("background: #252526;")
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(16, 3, 16, 3)
            row_layout.addWidget(btn)
            sl.addWidget(row)

        sl.addStretch()

    # ── Tabs ───────────────────────────────────────────────────────────────────

    def _build_tabs(self) -> QTabWidget:
        self._notebook = QTabWidget()
        editor_tab = QWidget()
        findings_tab = QWidget()
        batch_tab = QWidget()
        self._notebook.addTab(editor_tab, "Editor")
        self._notebook.addTab(findings_tab, "Findings")
        self._notebook.addTab(batch_tab, "Batch")
        self._build_tab_editor(editor_tab)
        self._build_tab_findings(findings_tab)
        self._build_tab_batch(batch_tab)
        return self._notebook

    # ── Editor tab ─────────────────────────────────────────────────────────────

    def _build_tab_editor(self, tab: QWidget) -> None:
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        in_lbl = QLabel("INPUT")
        in_lbl.setStyleSheet("color: #888888; font-size: 11px; font-weight: bold;")
        layout.addWidget(in_lbl)

        self._input_box = QTextEdit()
        self._input_box.setFont(_mono_font())
        self._input_box.setAcceptRichText(False)
        self._input_box.setLineWrapMode(QTextEdit.NoWrap)
        self._input_box.textChanged.connect(self._on_input_change)
        layout.addWidget(self._input_box, stretch=1)

        self._output_label = QLabel("OUTPUT  (masked)")
        self._output_label.setStyleSheet(
            "color: #888888; font-size: 11px; font-weight: bold; margin-top: 6px;")
        layout.addWidget(self._output_label)

        self._output_box = QTextEdit()
        self._output_box.setFont(_mono_font())
        self._output_box.setReadOnly(True)
        self._output_box.setLineWrapMode(QTextEdit.NoWrap)
        layout.addWidget(self._output_box, stretch=1)

    # ── Findings tab ───────────────────────────────────────────────────────────

    def _build_tab_findings(self, tab: QWidget) -> None:
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        header_row = QWidget()
        header_layout = QHBoxLayout(header_row)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(8)
        self._findings_label = QLabel("FINDINGS  \u2014  none")
        self._findings_label.setStyleSheet("color: #888888; font-size: 11px; font-weight: bold;")
        header_layout.addWidget(self._findings_label, stretch=1)
        self._findings_filter = QLineEdit()
        self._findings_filter.setPlaceholderText("Filter findings\u2026")
        self._findings_filter.setFixedWidth(200)
        self._findings_filter.setFixedHeight(24)
        self._findings_filter.setStyleSheet(
            "background:#2d2d2d; color:#d4d4d4; border:1px solid #555; border-radius:4px;"
            "padding:0 6px; font-size:12px;")
        self._findings_filter.textChanged.connect(self._filter_findings)
        header_layout.addWidget(self._findings_filter)
        layout.addWidget(header_row)

        self._tree = QTreeWidget()
        self._tree.setAlternatingRowColors(True)
        self._tree.setRootIsDecorated(False)
        self._tree.setUniformRowHeights(True)
        self._tree.setSelectionMode(QAbstractItemView.SingleSelection)
        self._tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._on_finding_right_click)
        self._tree.setHeaderLabels(["Pattern", "Category", "Conf", "Original", "Masked"])
        self._tree.setFont(_mono_font())
        for i, w in enumerate([140, 100, 56, 270, 270]):
            self._tree.setColumnWidth(i, w)
        self._tree.header().setStretchLastSection(True)
        layout.addWidget(self._tree)

    # ── Batch tab ──────────────────────────────────────────────────────────────

    def _build_tab_batch(self, tab: QWidget) -> None:
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        form = QWidget()
        form_layout = QGridLayout(form)
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setHorizontalSpacing(8)
        form_layout.setVerticalSpacing(6)
        form_layout.setColumnStretch(1, 1)

        for row, (label, attr, ph, browse_fn) in enumerate([
            ("Source folder:",        "_batch_src_edit",   "",                   self._browse_batch_src),
            ("Output folder:",        "_batch_dst_edit",   "",                   self._browse_batch_dst),
            ("Audit log (optional):", "_batch_audit_edit", "e.g. report.json",   self._browse_batch_audit),
        ]):
            lbl = QLabel(label)
            lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            form_layout.addWidget(lbl, row, 0)
            edit = QLineEdit()
            if ph:
                edit.setPlaceholderText(ph)
            setattr(self, attr, edit)
            form_layout.addWidget(edit, row, 1)
            browse_btn = QPushButton("Browse\u2026")
            browse_btn.setFixedWidth(80)
            browse_btn.setStyleSheet(
                "background: #3c3c3c; color: #d4d4d4; border: none; border-radius: 4px; padding: 4px 8px;")
            browse_btn.clicked.connect(browse_fn)
            form_layout.addWidget(browse_btn, row, 2)

        layout.addWidget(form)

        opts_row = QWidget()
        opts_layout = QHBoxLayout(opts_row)
        opts_layout.setContentsMargins(0, 0, 0, 0)
        self._batch_dryrun_cb = QCheckBox("Dry run (preview only — no files written)")
        self._batch_dryrun_cb.setStyleSheet("color: #d4d4d4;")
        opts_layout.addWidget(self._batch_dryrun_cb)
        opts_layout.addStretch()
        layout.addWidget(opts_row)

        self._batch_btn = QPushButton("Start Batch Scrub")
        self._batch_btn.setFixedHeight(36)
        self._batch_btn.clicked.connect(self._run_batch)
        layout.addWidget(self._batch_btn)

        self._batch_progress = QProgressBar()
        self._batch_progress.setRange(0, 100)
        self._batch_progress.setValue(0)
        self._batch_progress.setFixedHeight(6)
        self._batch_progress.setTextVisible(False)
        self._batch_progress.setStyleSheet(
            "QProgressBar { background: #3c3c3c; border: none; border-radius: 3px; }"
            "QProgressBar::chunk { background: #0e639c; border-radius: 3px; }"
        )
        self._batch_progress.hide()
        layout.addWidget(self._batch_progress)

        self._batch_log_box = QTextEdit()
        self._batch_log_box.setReadOnly(True)
        self._batch_log_box.setFont(_mono_font())
        layout.addWidget(self._batch_log_box, stretch=1)

    # ── Status bar ─────────────────────────────────────────────────────────────

    def _build_statusbar(self) -> None:
        sb = QStatusBar()
        self.setStatusBar(sb)
        lbl_style = "color: #555555; font-size: 11px;"
        sep_style = "color: #333333; font-size: 11px; padding: 0 4px;"

        self._status_format = QLabel("Format: text")
        self._status_format.setStyleSheet(lbl_style)
        self._status_chars = QLabel("0 chars")
        self._status_chars.setStyleSheet(lbl_style)
        self._status_findings = QLabel("0 findings")
        self._status_findings.setStyleSheet(lbl_style)
        version_lbl = QLabel(f"v{_VERSION}")
        version_lbl.setStyleSheet(lbl_style)

        for widget in [
            self._status_format,
            self._make_sep(sep_style),
            self._status_chars,
            self._make_sep(sep_style),
            self._status_findings,
        ]:
            sb.addWidget(widget)
        sb.addPermanentWidget(version_lbl)

    @staticmethod
    def _make_sep(style: str) -> QLabel:
        sep = QLabel("\u2502")
        sep.setStyleSheet(style)
        return sep

    # ── Key bindings ───────────────────────────────────────────────────────────

    def _bind_keys(self) -> None:
        QShortcut(QKeySequence("Ctrl+O"), self).activated.connect(self._open_file)
        QShortcut(QKeySequence("Ctrl+S"), self).activated.connect(self._save)

    # ── Event handlers ─────────────────────────────────────────────────────────

    def _on_input_change(self) -> None:
        text = self._input_box.toPlainText()
        n = len(text)
        self._status_chars.setText(f"{n:,} chars")
        # For normal edits, keep _full_text in sync with the box.
        # Skip the update when the box shows a truncated large-file display —
        # in that case _full_text was already set to the complete text by _set_input.
        if n <= _LARGE_FILE_DISPLAY_CHARS:
            self._full_text = text
        self._scrub_timer.start(300)

    def _on_style_change(self) -> None:
        style = self._resolve_mask_style()
        needs_char = style in ("partial", "full")
        for btn in self._mask_char_group.buttons():
            btn.setEnabled(needs_char)
        self._custom_mask_entry.setEnabled(needs_char)
        color = "#888888" if needs_char else "#444444"
        self._mask_char_header.setStyleSheet(
            f"color: {color}; font-size: 10px; font-weight: bold;"
            "padding: 14px 16px 4px 16px; background: #252526;")
        self._on_setting_change()

    def _on_setting_change(self) -> None:
        self._scrub_timer.start(100)

    def _on_confidence_change(self, value: int) -> None:
        self._min_confidence = value / 100.0
        self._conf_label.setText(f"{value}%")
        self._scrub_timer.start(100)

    def _on_profile_select(self, name: str) -> None:
        if not name or name == "(none)":
            return
        profile = get_profile(name)
        if not profile:
            return
        for btn in self._mask_style_group.buttons():
            if btn.property("mask_value") == profile.mask_style:
                btn.setChecked(True)
                break
        preset_vals = {btn.property("char_value") for btn in self._mask_char_group.buttons()}
        if profile.mask_char in preset_vals:
            for btn in self._mask_char_group.buttons():
                if btn.property("char_value") == profile.mask_char:
                    btn.setChecked(True)
                    break
        else:
            self._mask_char_custom_rb.setChecked(True)
            self._custom_mask_entry.setText(profile.mask_char)
        disabled = set(profile.disabled_patterns)
        for pname, cb in self._pattern_cbs.items():
            cb.setChecked(pname not in disabled)
        self._allowlist = set(profile.allowlist)
        self._on_style_change()

    def _set_group(self, patterns: list[tuple[str, str]], enabled: bool) -> None:
        for name, _ in patterns:
            if name in self._pattern_cbs:
                self._pattern_cbs[name].setChecked(enabled)
        self._scrub()

    def _on_finding_right_click(self, pos) -> None:
        item = self._tree.itemAt(pos)
        if not item:
            return
        original = item.text(3)
        masked = item.text(4)
        menu = QMenu(self)
        copy_orig = menu.addAction(f"Copy original: {original[:40]}")
        copy_masked = menu.addAction(f"Copy masked: {masked[:40]}")
        menu.addSeparator()
        allowlist_action = menu.addAction(f"Add to allowlist: {original[:40]}")
        triggered = menu.exec(self._tree.viewport().mapToGlobal(pos))
        if triggered == copy_orig:
            QApplication.clipboard().setText(original)
            self._show_toast("Copied original")
        elif triggered == copy_masked:
            QApplication.clipboard().setText(masked)
            self._show_toast("Copied masked")
        elif triggered == allowlist_action:
            self._add_to_allowlist(original)

    def _add_to_allowlist(self, value: str) -> None:
        self._allowlist.add(value)
        self._scrub()
        self._show_toast(f"Allowlisted: {value[:30]}")

    # ── File I/O ────────────────────────────────────────────────────────────────

    def _open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open file to scrub", "",
            "All supported (*.txt *.json *.csv *.log *.md *.yaml *.yml *.env);;"
            "Text files (*.txt *.log *.md);;JSON files (*.json);;"
            "CSV files (*.csv);;All files (*.*)",
        )
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            QMessageBox.critical(self, "LogScrub", f"Cannot read file:\n{exc}")
            return
        suffix = Path(path).suffix.lower()
        self._file_format = {".json": "json", ".csv": "csv"}.get(suffix, "text")
        self._current_file = Path(path).name
        self._token_map = {}
        self._set_input(content)
        self.setWindowTitle(f"Datascrub \u2014 {self._current_file}")
        self._update_status_format()

    # ── Scrub engine ────────────────────────────────────────────────────────────

    def _scrub(self) -> None:
        self._scrub_timer.stop()
        self._scrub_gen += 1
        gen = self._scrub_gen

        # Use full text for scrubbing (not the potentially truncated display)
        text = self._full_text if self._full_text else self._input_box.toPlainText()
        if not text.strip():
            return
        self._status_findings.setText("Scanning…")
        disabled = frozenset(n for n, cb in self._pattern_cbs.items() if not cb.isChecked())
        mask_char = self._resolve_mask_char()
        mask_style = self._resolve_mask_style()
        if mask_style != "token":
            self._token_map = {}
        token_map_copy = dict(self._token_map)
        kwargs: dict = dict(
            categories=None,
            extra_patterns=self._extra_patterns + self._custom_patterns,
            mask_char=mask_char,
            mask_style=mask_style,
            disabled_patterns=disabled,
            allowlist=frozenset(self._allowlist),
            token_map=token_map_copy,
            min_confidence=self._min_confidence,
        )
        file_format = self._file_format
        bridge = self._bridge

        def _worker() -> None:
            if file_format == "json":
                result = scrub_json(text, **kwargs)
            elif file_format == "csv":
                result = scrub_csv(text, **kwargs)
            else:
                result = scrub(text, **kwargs)
            bridge.scrub_done.emit(result, text, file_format, gen, token_map_copy)

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_scrub_result(
        self,
        result: ScrubResult,
        text: str,
        file_format: str,
        gen: int,
        worker_token_map: dict,
    ) -> None:
        if gen != self._scrub_gen:
            return
        self._token_map = worker_token_map
        self._last_result = result

        # ── Output with diff highlighting ──────────────────────────────────────
        self._output_box.clear()
        cursor = self._output_box.textCursor()

        plain_fmt = QTextCharFormat()
        plain_fmt.setForeground(QColor("#d4d4d4"))

        masked_fmt = QTextCharFormat()
        masked_fmt.setForeground(QColor("#ff8080"))
        masked_fmt.setBackground(QColor("#5a1a1a"))
        masked_fmt.setFontWeight(QFont.Bold)

        if file_format == "text" and result.findings:
            pos = 0
            for f in result.findings:
                if f.start < pos:
                    continue
                if f.start > pos:
                    cursor.setCharFormat(plain_fmt)
                    cursor.insertText(text[pos:f.start])
                cursor.setCharFormat(masked_fmt)
                cursor.insertText(f.masked)
                pos = f.end
            if pos < len(text):
                cursor.setCharFormat(plain_fmt)
                cursor.insertText(text[pos:])
        else:
            cursor.setCharFormat(plain_fmt)
            cursor.insertText(result.text)

        # ── Findings table ─────────────────────────────────────────────────────
        self._tree.clear()
        low_conf_color = QColor("#d4a060")
        for f in result.findings:
            orig = f.original if len(f.original) <= 44 else f.original[:41] + "\u2026"
            item = QTreeWidgetItem([
                f.pattern_name, f.category,
                f"{f.confidence * 100:.0f}%", orig, f.masked,
            ])
            if f.confidence < 0.9:
                for col in range(5):
                    item.setForeground(col, low_conf_color)
            self._tree.addTopLevelItem(item)

        count = result.finding_count
        self._findings_label.setText(
            f"FINDINGS  \u2014  {count} detected" if count else "FINDINGS  \u2014  none")
        self._output_label.setText(
            f"OUTPUT  (masked \u2014 {count} replacement{'s' if count != 1 else ''})"
            if count else "OUTPUT  (no sensitive data found)")
        self._status_findings.setText(f"{count} finding{'s' if count != 1 else ''}")
        self._filter_findings(self._findings_filter.text())

    # ── Output actions ──────────────────────────────────────────────────────────

    def _copy(self) -> None:
        if self._last_result is None:
            QMessageBox.information(self, "LogScrub", "Nothing to copy yet.")
            return
        QApplication.clipboard().setText(self._last_result.text)
        self._show_toast("Copied to clipboard")

    def _save(self) -> None:
        if self._last_result is None:
            QMessageBox.information(self, "LogScrub", "Nothing to save yet.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save masked output", "",
            "Text (*.txt);;JSON (*.json);;CSV (*.csv);;All (*.*)",
        )
        if not path:
            return
        try:
            Path(path).write_text(self._last_result.text, encoding="utf-8")
            self._show_toast(f"Saved  {Path(path).name}")
        except OSError as exc:
            QMessageBox.critical(self, "LogScrub", f"Cannot save:\n{exc}")

    def _export_audit(self, fmt: str = "json") -> None:
        if self._last_result is None:
            QMessageBox.information(self, "LogScrub", "Nothing to export yet.")
            return
        filt = "CSV (*.csv);;All (*.*)" if fmt == "csv" else "JSON (*.json);;All (*.*)"
        path, _ = QFileDialog.getSaveFileName(self, "Export audit log", "", filt)
        if not path:
            return
        source = self._current_file or "input"
        try:
            if path.lower().endswith(".csv"):
                audit_csv([(source, self._last_result)], path)
            else:
                audit_json([(source, self._last_result)], path)
            self._show_toast(f"Audit log saved  {Path(path).name}")
        except OSError as exc:
            QMessageBox.critical(self, "LogScrub", f"Cannot save:\n{exc}")

    def _show_report(self) -> None:
        if self._last_result is None:
            QMessageBox.information(self, "LogScrub", "Nothing to report yet.")
            return
        source = self._current_file or "input"
        report = export_text([(source, self._last_result)], include_original=False)
        dlg = QDialog(self)
        dlg.setWindowTitle("De-identification Report")
        dlg.resize(640, 480)
        layout = QVBoxLayout(dlg)
        box = QTextEdit()
        box.setReadOnly(True)
        box.setFont(_mono_font())
        box.setPlainText(report)
        layout.addWidget(box)
        dlg.exec()

    def _clear(self) -> None:
        self._input_box.clear()
        self._output_box.clear()
        self._tree.clear()
        self._last_result = None
        self._file_format = "text"
        self._current_file = ""
        self._full_text = ""
        self._token_map = {}
        self.setWindowTitle("LogScrub")
        self._findings_label.setText("FINDINGS  \u2014  none")
        self._output_label.setText("OUTPUT  (masked)")
        self._status_chars.setText("0 chars")
        self._status_findings.setText("0 findings")
        self._update_status_format()

    # ── Allowlist dialog ────────────────────────────────────────────────────────

    def _show_allowlist(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("Allowlist Manager")
        dlg.resize(500, 420)
        dlg.setWindowModality(Qt.ApplicationModal)
        layout = QVBoxLayout(dlg)

        lbl = QLabel("Values in this list will never be masked:")
        lbl.setStyleSheet("color: #aaaaaa;")
        layout.addWidget(lbl)

        list_w = QListWidget()
        list_w.setFont(_mono_font())
        for v in sorted(self._allowlist):
            list_w.addItem(v)
        layout.addWidget(list_w, stretch=1)

        status_lbl = QLabel("")
        status_lbl.setStyleSheet("color: #888888; font-size: 11px;")
        layout.addWidget(status_lbl)

        entry_row = QWidget()
        entry_layout = QHBoxLayout(entry_row)
        entry_layout.setContentsMargins(0, 0, 0, 0)
        entry_layout.setSpacing(6)
        entry_edit = QLineEdit()
        entry_edit.setPlaceholderText("Add value\u2026")
        entry_layout.addWidget(entry_edit, stretch=1)

        def _add() -> None:
            val = entry_edit.text().strip()
            if not val:
                return
            if val in self._allowlist:
                status_lbl.setStyleSheet("color: #d4a060; font-size: 11px;")
                status_lbl.setText(f"Already in list: {val[:40]}")
                return
            self._allowlist.add(val)
            items = [list_w.item(i).text() for i in range(list_w.count())]
            idx = next((i for i, v in enumerate(items) if v > val), len(items))
            list_w.insertItem(idx, val)
            entry_edit.clear()
            status_lbl.setStyleSheet("color: #60e060; font-size: 11px;")
            status_lbl.setText(f"Added: {val[:40]}")
            self._scrub()

        def _remove() -> None:
            row = list_w.currentRow()
            if row < 0:
                return
            val = list_w.item(row).text()
            self._allowlist.discard(val)
            list_w.takeItem(row)
            status_lbl.setStyleSheet("color: #888888; font-size: 11px;")
            status_lbl.setText(f"Removed: {val[:40]}")
            self._scrub()

        def _clear_all() -> None:
            if not self._allowlist:
                return
            self._allowlist.clear()
            list_w.clear()
            status_lbl.setStyleSheet("color: #888888; font-size: 11px;")
            status_lbl.setText("Allowlist cleared.")
            self._scrub()

        entry_edit.returnPressed.connect(_add)
        for text, fn, style in [
            ("Add", _add, None),
            ("Remove", _remove, "background:#3c3c3c;color:#d4d4d4;border:none;border-radius:4px;padding:4px 8px;"),
            ("Clear all", _clear_all, "background:#6e2020;color:#d4d4d4;border:none;border-radius:4px;padding:4px 8px;"),
        ]:
            b = QPushButton(text)
            if style:
                b.setStyleSheet(style)
            b.clicked.connect(fn)
            entry_layout.addWidget(b)

        layout.addWidget(entry_row)
        entry_edit.setFocus()
        dlg.exec()

    # ── Custom pattern editor ───────────────────────────────────────────────────

    def _show_pattern_editor(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("Custom Pattern Editor")
        dlg.resize(640, 580)
        dlg.setWindowModality(Qt.ApplicationModal)
        layout = QVBoxLayout(dlg)

        form = QWidget()
        form_layout = QGridLayout(form)
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setColumnStretch(1, 1)
        fields: dict[str, QLineEdit] = {}
        for i, (lbl_text, ph) in enumerate([
            ("Name:", "my_secret"),
            ("Category:", "credentials"),
            ("Regex:", r"(?i)my_token[=:\s]+([a-zA-Z0-9]{20,})"),
        ]):
            lbl = QLabel(lbl_text)
            lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            form_layout.addWidget(lbl, i, 0)
            entry = QLineEdit()
            entry.setPlaceholderText(ph)
            form_layout.addWidget(entry, i, 1)
            fields[lbl_text] = entry
        layout.addWidget(form)

        status_lbl = QLabel("")
        status_lbl.setStyleSheet("color: #888888; font-size: 11px;")
        layout.addWidget(status_lbl)

        # Test area
        test_frame = QFrame()
        test_frame.setStyleSheet("QFrame { border: 1px solid #3c3c3c; border-radius: 4px; }")
        test_layout = QGridLayout(test_frame)
        test_layout.setColumnStretch(1, 1)
        test_layout.addWidget(QLabel("Test:"), 0, 0)
        test_entry = QLineEdit()
        test_entry.setPlaceholderText("Paste sample text to verify a match\u2026")
        test_layout.addWidget(test_entry, 0, 1)
        test_btn = QPushButton("Test")
        test_btn.setFixedWidth(70)
        test_layout.addWidget(test_btn, 0, 2)
        test_result = QLabel("")
        test_result.setStyleSheet("color: #888888; font-size: 11px;")
        test_layout.addWidget(test_result, 1, 0, 1, 3)
        layout.addWidget(test_frame)

        _TIMEOUT = 2.0
        _serial = [0]

        def _test() -> None:
            pat_str = fields["Regex:"].text().strip()
            sample = test_entry.text()
            if not pat_str:
                test_result.setStyleSheet("color: #d4a060; font-size: 11px;")
                test_result.setText("Enter a regex first.")
                return
            try:
                re.compile(pat_str)
            except re.error as e:
                test_result.setStyleSheet("color: #e06060; font-size: 11px;")
                test_result.setText(f"Regex error: {e}")
                return

            _serial[0] += 1
            serial = _serial[0]
            test_result.setStyleSheet("color: #888888; font-size: 11px;")
            test_result.setText("Testing\u2026")

            def _run() -> None:
                ctx = multiprocessing.get_context("spawn")
                mp_q: multiprocessing.Queue = ctx.Queue()
                p = ctx.Process(
                    target=_regex_test_mp_worker,
                    args=(pat_str, sample, mp_q),
                    daemon=True,
                )
                p.start()
                p.join(timeout=_TIMEOUT)
                if p.is_alive():
                    p.terminate()
                    p.join()
                    if serial == _serial[0]:
                        QTimer.singleShot(0, lambda: (
                            test_result.setStyleSheet("color: #e06060; font-size: 11px;"),
                            test_result.setText("Timed out — possible ReDoS risk."),
                        ))
                    return
                if serial != _serial[0]:
                    return
                try:
                    result_val = mp_q.get_nowait()
                except Exception:
                    result_val = []
                if isinstance(result_val, Exception):
                    err = result_val
                    QTimer.singleShot(0, lambda: (
                        test_result.setStyleSheet("color: #e06060; font-size: 11px;"),
                        test_result.setText(f"Error: {err}"),
                    ))
                    return
                matches = result_val
                if not matches:
                    QTimer.singleShot(0, lambda: (
                        test_result.setStyleSheet("color: #d4a060; font-size: 11px;"),
                        test_result.setText("No match."),
                    ))
                else:
                    preview = ", ".join(
                        repr(m if isinstance(m, str) else m[0]) for m in matches[:5]
                    )
                    msg = f"{len(matches)} match(es): {preview}"
                    QTimer.singleShot(0, lambda: (
                        test_result.setStyleSheet("color: #60e060; font-size: 11px;"),
                        test_result.setText(msg),
                    ))

            threading.Thread(target=_run, daemon=True).start()

        test_entry.textChanged.connect(lambda _: _test())
        test_btn.clicked.connect(_test)

        # Existing custom patterns list
        list_lbl = QLabel("Custom patterns:")
        list_lbl.setStyleSheet("color: #888888; font-size: 11px; font-weight: bold;")
        layout.addWidget(list_lbl)
        list_w = QListWidget()
        list_w.setFont(_mono_font())
        for p in self._custom_patterns:
            list_w.addItem(f"{p.name}  [{p.category}]  {p.regex.pattern[:50]}")
        layout.addWidget(list_w, stretch=1)

        def _add() -> None:
            name = fields["Name:"].text().strip()
            cat = fields["Category:"].text().strip() or "custom"
            pat_str = fields["Regex:"].text().strip()
            if not name or not pat_str:
                status_lbl.setStyleSheet("color: #e06060; font-size: 11px;")
                status_lbl.setText("Name and Regex are required.")
                return
            if any(p.name == name for p in self._custom_patterns):
                status_lbl.setStyleSheet("color: #d4a060; font-size: 11px;")
                status_lbl.setText(f"Name already exists: {name}")
                return
            try:
                compiled = re.compile(pat_str)
            except re.error as e:
                status_lbl.setStyleSheet("color: #e06060; font-size: 11px;")
                status_lbl.setText(f"Regex error: {e}")
                return

            def _masker(m: re.Match, _c=compiled) -> str:
                g1 = m.group(1) if _c.groups >= 1 else None
                val = g1 if g1 is not None else m.group(0)
                return val[:2] + "*" * max(4, len(val) - 2) if len(val) > 4 else "****"

            p = Pattern(name=name, category=cat, regex=compiled, masker=_masker, confidence=0.9)
            self._custom_patterns.append(p)
            list_w.addItem(f"{name}  [{cat}]  {pat_str[:50]}")
            status_lbl.setStyleSheet("color: #60e060; font-size: 11px;")
            status_lbl.setText(f"Added: {name}")
            for f in fields.values():
                f.clear()
            self._scrub()

        def _remove() -> None:
            row = list_w.currentRow()
            if row < 0:
                return
            self._custom_patterns.pop(row)
            list_w.takeItem(row)
            status_lbl.setStyleSheet("color: #888888; font-size: 11px;")
            status_lbl.setText("Pattern removed.")
            self._scrub()

        fields["Regex:"].returnPressed.connect(_add)
        btn_row = QWidget()
        btn_row_layout = QHBoxLayout(btn_row)
        btn_row_layout.setContentsMargins(0, 0, 0, 0)
        add_btn = QPushButton("Add pattern")
        add_btn.clicked.connect(_add)
        btn_row_layout.addWidget(add_btn)
        rem_btn = QPushButton("Remove selected")
        rem_btn.setStyleSheet(
            "background:#3c3c3c;color:#d4d4d4;border:none;border-radius:4px;padding:5px 14px;")
        rem_btn.clicked.connect(_remove)
        btn_row_layout.addWidget(rem_btn)
        btn_row_layout.addStretch()
        layout.addWidget(btn_row)
        fields["Name:"].setFocus()
        dlg.exec()

    # ── Profile save dialog ─────────────────────────────────────────────────────

    def _save_profile_dialog(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("Save Profile")
        dlg.resize(360, 180)
        dlg.setWindowModality(Qt.ApplicationModal)
        layout = QVBoxLayout(dlg)
        layout.addWidget(QLabel("Profile name:"))
        entry = QLineEdit()
        layout.addWidget(entry)
        status = QLabel("")
        status.setStyleSheet("color: #888888; font-size: 11px;")
        layout.addWidget(status)

        def _save() -> None:
            name = entry.text().strip()
            if not name:
                return
            disabled = [n for n, cb in self._pattern_cbs.items() if not cb.isChecked()]
            p = Profile(
                name=name,
                mask_style=self._resolve_mask_style(),
                mask_char=self._resolve_mask_char(),
                disabled_patterns=disabled,
                allowlist=list(self._allowlist),
            )
            try:
                save_profile(p)
            except FileExistsError as exc:
                status.setStyleSheet("color: #e06060; font-size: 11px;")
                status.setText(str(exc))
                return
            # Rebuild combo without triggering _on_profile_select mid-update
            self._profile_combo.blockSignals(True)
            self._profile_combo.clear()
            self._profile_combo.addItem("(none)")
            self._profile_combo.addItems([pr.name for pr in list_profiles()])
            self._profile_combo.setCurrentText(name)
            self._profile_combo.blockSignals(False)
            status.setStyleSheet("color: #60e060; font-size: 11px;")
            status.setText(f"Saved: {name}")
            QTimer.singleShot(1200, dlg.accept)

        entry.returnPressed.connect(_save)
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(_save)
        layout.addWidget(save_btn)
        entry.setFocus()
        dlg.exec()

    def _import_profile(self) -> None:
        """Import a profile from a JSON or YAML file into the user profile store."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Import profile", "",
            "Profile files (*.json *.yaml *.yml);;All files (*.*)",
        )
        if not path:
            return
        try:
            from .profiles import load_profile_from_path, save_profile
            p = load_profile_from_path(path)
            save_profile(p)
        except Exception as exc:
            QMessageBox.critical(self, "LogScrub", f"Import failed:\n{exc}")
            return
        self._profile_combo.blockSignals(True)
        self._profile_combo.clear()
        self._profile_combo.addItem("(none)")
        from .profiles import list_profiles as _lp
        self._profile_combo.addItems([pr.name for pr in _lp()])
        self._profile_combo.setCurrentText(p.name)
        self._profile_combo.blockSignals(False)
        self._show_toast(f"Imported profile: {p.name}")

    def _export_profile(self) -> None:
        """Export the currently selected profile to a JSON or YAML file."""
        name = self._profile_combo.currentText()
        if not name or name == "(none)":
            QMessageBox.information(self, "LogScrub", "Select a profile to export first.")
            return
        from .profiles import get_profile
        p = get_profile(name)
        if p is None:
            QMessageBox.warning(self, "LogScrub", f"Profile not found: {name!r}")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export profile", f"{name}.json",
            "JSON (*.json);;YAML (*.yaml);;All files (*.*)",
        )
        if not path:
            return
        try:
            import json as _json
            import yaml as _yaml  # type: ignore[import]
            text = (_yaml.dump(p.to_dict(), default_flow_style=False, allow_unicode=True)
                    if path.lower().endswith((".yaml", ".yml"))
                    else _json.dumps(p.to_dict(), indent=2, ensure_ascii=False))
            Path(path).write_text(text, encoding="utf-8")
        except Exception as exc:
            QMessageBox.critical(self, "LogScrub", f"Export failed:\n{exc}")
            return
        self._show_toast(f"Profile exported: {Path(path).name}")

    # ── Batch scrub ─────────────────────────────────────────────────────────────

    def _browse_batch_src(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select source folder")
        if d:
            self._batch_src_edit.setText(d)

    def _browse_batch_dst(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select output folder")
        if d:
            self._batch_dst_edit.setText(d)

    def _browse_batch_audit(self) -> None:
        p, _ = QFileDialog.getSaveFileName(
            self, "Audit log path", "", "JSON (*.json);;CSV (*.csv)")
        if p:
            self._batch_audit_edit.setText(p)

    def _batch_log_line(self, line: str) -> None:
        self._batch_log_box.append(line)

    def _on_batch_progress(self, done: int, total: int) -> None:
        if total > 0:
            self._batch_progress.setValue(int(done * 100 / total))

    def _on_batch_done(self) -> None:
        self._batch_btn.setEnabled(True)
        self._batch_btn.setText("Start Batch Scrub")
        self._batch_progress.setValue(100)
        QTimer.singleShot(1500, self._batch_progress.hide)

    def _run_batch(self) -> None:
        src = self._batch_src_edit.text().strip()
        dst = self._batch_dst_edit.text().strip()
        if not src or not dst:
            QMessageBox.warning(self, "LogScrub", "Set source and output folders first.")
            return
        src_path = Path(src)
        dst_path = Path(dst)
        if not src_path.is_dir():
            QMessageBox.critical(self, "LogScrub", "Source folder not found.")
            return

        self._batch_btn.setEnabled(False)
        self._batch_btn.setText("Running\u2026")
        self._batch_log_box.clear()
        self._batch_progress.setValue(0)
        self._batch_progress.show()

        disabled = frozenset(n for n, cb in self._pattern_cbs.items() if not cb.isChecked())
        mask_char = self._resolve_mask_char()
        mask_style = self._resolve_mask_style()
        audit_path_str = self._batch_audit_edit.text().strip()
        allowlist = frozenset(self._allowlist)
        all_patterns = self._extra_patterns + self._custom_patterns
        dry_run = self._batch_dryrun_cb.isChecked()
        min_conf = self._min_confidence
        bridge = self._bridge

        def _worker() -> None:
            exts = {".txt", ".json", ".csv", ".log", ".yaml", ".yml", ".xml", ".md"}
            paths = [p for p in src_path.rglob("*") if p.is_file() and p.suffix.lower() in exts]
            if not paths:
                bridge.batch_log.emit("No supported files found.")
                bridge.batch_done.emit()
                return
            all_results = []
            token_map: dict = {}
            total = 0
            n_paths = len(paths)
            for idx, path in enumerate(sorted(paths), 1):
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                    fmt = {".json": "json", ".csv": "csv"}.get(path.suffix.lower(), "text")
                    kw = dict(extra_patterns=all_patterns, mask_char=mask_char,
                              mask_style=mask_style, disabled_patterns=disabled,
                              allowlist=allowlist, token_map=token_map,
                              min_confidence=min_conf)
                    if fmt == "json":
                        result = scrub_json(text, **kw)
                    elif fmt == "csv":
                        result = scrub_csv(text, **kw)
                    else:
                        result = scrub(text, **kw)
                    rel = path.relative_to(src_path)
                    if dry_run:
                        bridge.batch_log.emit(f"  [dry-run]  {rel}  ({result.finding_count} findings would be masked)")
                    else:
                        out = dst_path / rel
                        out.parent.mkdir(parents=True, exist_ok=True)
                        out.write_text(result.text, encoding="utf-8")
                        bridge.batch_log.emit(f"  \u2713  {rel}  ({result.finding_count} findings)")
                    total += result.finding_count
                    all_results.append((str(path), result))
                except Exception as e:
                    bridge.batch_log.emit(f"  \u2717  {path.name}: {e}")
                bridge.batch_progress.emit(idx, n_paths)
            action = "would mask" if dry_run else "masked"
            bridge.batch_log.emit(f"\nDone: {len(all_results)} files, {total} findings {action}.")
            if audit_path_str and all_results and not dry_run:
                try:
                    ap = Path(audit_path_str)
                    if ap.suffix.lower() == ".csv":
                        audit_csv(all_results, ap)
                    else:
                        audit_json(all_results, ap)
                    bridge.batch_log.emit(f"Audit log: {audit_path_str}")
                except Exception as e:
                    bridge.batch_log.emit(f"Audit error: {e}")
            bridge.batch_done.emit()

        threading.Thread(target=_worker, daemon=True).start()

    # ── Export / Report dialog ──────────────────────────────────────────────────

    def _show_export_dialog(self) -> None:
        if self._last_result is None:
            QMessageBox.information(self, "LogScrub", "Nothing to export yet.")
            return
        dlg = QDialog(self)
        dlg.setWindowTitle("Export / Report")
        dlg.resize(300, 220)
        dlg.setWindowModality(Qt.ApplicationModal)
        layout = QVBoxLayout(dlg)
        hdr = QLabel("Export options:")
        hdr.setStyleSheet("font-size: 13px; font-weight: bold; padding: 8px 0;")
        layout.addWidget(hdr)

        def _do(fn) -> None:
            dlg.accept()
            fn()

        for text, fn, secondary in [
            ("Save masked output\u2026", self._save, False),
            ("Audit log (JSON)\u2026", lambda: self._export_audit("json"), True),
            ("Audit log (CSV)\u2026",  lambda: self._export_audit("csv"),  True),
            ("View report",            self._show_report,                  True),
        ]:
            btn = QPushButton(text)
            btn.setFixedHeight(34)
            if secondary:
                btn.setStyleSheet(
                    "background:#3c3c3c;color:#d4d4d4;border:none;border-radius:4px;padding:5px 14px;")
            btn.clicked.connect(lambda checked=False, f=fn: _do(f))
            layout.addWidget(btn)

        # Token map row (only useful when mask_style == token)
        if self._token_map:
            sep = QLabel("")
            sep.setFixedHeight(8)
            layout.addWidget(sep)
            tm_lbl = QLabel("Token map:")
            tm_lbl.setStyleSheet("font-size: 11px; color: #9cdcfe; padding-left: 2px;")
            layout.addWidget(tm_lbl)
            tm_row = QWidget()
            tm_row_layout = QHBoxLayout(tm_row)
            tm_row_layout.setContentsMargins(0, 0, 0, 0)
            btn_load_tm = QPushButton("Load\u2026")
            btn_save_tm = QPushButton("Save\u2026")
            for b in (btn_load_tm, btn_save_tm):
                b.setFixedHeight(28)
                b.setStyleSheet(
                    "background:#3c3c3c;color:#d4d4d4;border:none;border-radius:4px;padding:4px 12px;")
            def _load_tm() -> None:
                path, _ = QFileDialog.getOpenFileName(
                    self, "Load token map", "", "JSON (*.json);;All files (*.*)")
                if not path:
                    return
                try:
                    data = json.loads(Path(path).read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        self._token_map.update(data)
                        self._show_toast("Token map loaded")
                        dlg.accept()
                    else:
                        QMessageBox.warning(self, "LogScrub", "Token map must be a JSON object.")
                except Exception as exc:
                    QMessageBox.critical(self, "LogScrub", f"Load failed:\n{exc}")
            def _save_tm() -> None:
                path, _ = QFileDialog.getSaveFileName(
                    self, "Save token map", "token_map.json", "JSON (*.json)")
                if not path:
                    return
                try:
                    Path(path).write_text(
                        json.dumps(self._token_map, indent=2), encoding="utf-8")
                    self._show_toast("Token map saved")
                    dlg.accept()
                except Exception as exc:
                    QMessageBox.critical(self, "LogScrub", f"Save failed:\n{exc}")
            btn_load_tm.clicked.connect(_load_tm)
            btn_save_tm.clicked.connect(_save_tm)
            tm_row_layout.addWidget(btn_load_tm)
            tm_row_layout.addWidget(btn_save_tm)
            layout.addWidget(tm_row)

        layout.addStretch()
        dlg.exec()

    # ── Helpers ─────────────────────────────────────────────────────────────────

    def _resolve_mask_style(self) -> str:
        btn = self._mask_style_group.checkedButton()
        return btn.property("mask_value") if btn else "partial"

    def _resolve_mask_char(self) -> str:
        btn = self._mask_char_group.checkedButton()
        if btn is None:
            return "*"
        val = btn.property("char_value")
        if val == "__custom__":
            custom = self._custom_mask_entry.text()
            return custom[0] if custom else "*"
        return val

    def _set_input(self, text: str) -> None:
        self._full_text = text
        # Truncate display for very large files — scrub still runs on the full text
        if len(text) > _LARGE_FILE_DISPLAY_CHARS:
            display = text[:_LARGE_FILE_DISPLAY_CHARS]
            kb = len(text) // 1024
            self._input_box.setPlainText(
                display + f"\n\n[\u2026 {kb:,} KB total — display truncated, scrub runs on full file]")
        else:
            self._input_box.setPlainText(text)
        # Note: setPlainText already fires textChanged → _on_input_change; no explicit call needed.

    def _update_status_format(self) -> None:
        label = {"json": "Format: JSON", "csv": "Format: CSV"}.get(
            self._file_format, "Format: text")
        if self._current_file:
            label += f"  \u00b7  {self._current_file}"
        self._status_format.setText(label)

    def _show_toast(self, message: str) -> None:
        original = self.windowTitle()
        self.setWindowTitle(f"Datascrub \u2014 {message}")
        QTimer.singleShot(2500, lambda: self.setWindowTitle(original))

    # ── Findings filter ─────────────────────────────────────────────────────────

    def _filter_findings(self, text: str) -> None:
        needle = text.strip().lower()
        for i in range(self._tree.topLevelItemCount()):
            item = self._tree.topLevelItem(i)
            visible = not needle or any(
                needle in item.text(col).lower() for col in range(5)
            )
            item.setHidden(not visible)

    # ── Drag-and-drop ──────────────────────────────────────────────────────────

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:
        urls = event.mimeData().urls()
        if not urls:
            return
        path = Path(urls[0].toLocalFile())
        if not path.is_file():
            return
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            QMessageBox.critical(self, "LogScrub", f"Cannot read file:\n{exc}")
            return
        suffix = path.suffix.lower()
        self._file_format = {".json": "json", ".csv": "csv"}.get(suffix, "text")
        self._current_file = path.name
        self._token_map = {}
        self._set_input(content)
        self.setWindowTitle(f"datascrub \u2014 {path.name}")
        self._update_status_format()

    # ── Settings persistence ───────────────────────────────────────────────────

    def _load_settings(self) -> None:
        s = QSettings("logscrub", "logscrub")
        geom = s.value("geometry")
        if geom:
            self.restoreGeometry(geom)
        mask_style = s.value("mask_style", "partial")
        for btn in self._mask_style_group.buttons():
            if btn.property("mask_value") == mask_style:
                btn.setChecked(True)
                break
        mask_char = s.value("mask_char", "*")
        matched = False
        for btn in self._mask_char_group.buttons():
            val = btn.property("char_value")
            if val != "__custom__" and val == mask_char:
                btn.setChecked(True)
                matched = True
                break
        if not matched:
            self._mask_char_custom_rb.setChecked(True)
            self._custom_mask_entry.setText(mask_char)
        disabled = set(s.value("disabled_patterns", []) or [])
        for name, cb in self._pattern_cbs.items():
            cb.setChecked(name not in disabled)
        confidence = int(s.value("min_confidence_pct", 0) or 0)
        self._conf_slider.setValue(confidence)
        # Allowlist
        raw_allowlist = s.value("allowlist", []) or []
        self._allowlist = set(raw_allowlist)
        # Custom patterns
        raw_patterns = s.value("custom_patterns", []) or []
        for item in raw_patterns:
            try:
                name = item["name"]
                cat = item.get("category", "custom")
                pat_str = item["regex"]
                compiled = re.compile(pat_str)

                def _masker(m: re.Match, _c=compiled) -> str:
                    g1 = m.group(1) if _c.groups >= 1 else None
                    val = g1 if g1 is not None else m.group(0)
                    return val[:2] + "*" * max(4, len(val) - 2) if len(val) > 4 else "****"

                self._custom_patterns.append(
                    Pattern(name=name, category=cat, regex=compiled,
                            masker=_masker, confidence=item.get("confidence", 0.9))
                )
            except Exception:
                pass  # skip corrupt entries silently
        self._on_style_change()

    def _save_settings(self) -> None:
        s = QSettings("logscrub", "logscrub")
        s.setValue("geometry", self.saveGeometry())
        s.setValue("mask_style", self._resolve_mask_style())
        s.setValue("mask_char", self._resolve_mask_char())
        s.setValue("disabled_patterns",
                   [n for n, cb in self._pattern_cbs.items() if not cb.isChecked()])
        s.setValue("min_confidence_pct", self._conf_slider.value())
        s.setValue("allowlist", sorted(self._allowlist))
        s.setValue("custom_patterns", [
            {"name": p.name, "category": p.category,
             "regex": p.regex.pattern, "confidence": p.confidence}
            for p in self._custom_patterns
        ])

    def closeEvent(self, event) -> None:
        self._save_settings()
        super().closeEvent(event)


# ── Application entry point ────────────────────────────────────────────────────


def main() -> None:
    import os
    os.environ.setdefault("PYTHONUTF8", "1")
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(_DARK_QSS)
    window = LogScrubApp()
    window.show()
    sys.exit(app.exec())
