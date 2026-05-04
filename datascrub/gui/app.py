"""
CustomTkinter GUI for datascrub — v2.0

New in v2:
- Policy profile selector (GDPR, HIPAA, SOC2, Minimal, user-defined)
- Diff view — highlights changed spans instead of a separate output box
- Confidence column in findings table
- Allowlist manager — add/remove literal values to skip
- Custom pattern editor — create and save regex patterns via UI
- Batch mode panel — scrub entire folders
- De-identification report viewer
- Audit log export (JSON or CSV)
"""

from __future__ import annotations

import sys
import re
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from typing import Sequence

import customtkinter as ctk

from ..engine import scrub, ScrubResult
from ..handlers import scrub_json, scrub_csv
from ..patterns import Pattern
from ..audit import export_json as audit_json, export_csv as audit_csv, export_text
from ..profiles import list_profiles, save_profile, get_profile, Profile

# ── Theme ──────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

_VERSION = "2.0.0"

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
        ("email",  "Email"),
        ("ssn",    "SSN"),
        ("phone",  "Phone"),
    ]),
    ("Credentials", [
        ("jwt",                "JWT"),
        ("bearer_token",       "Bearer token"),
        ("openai_key",         "OpenAI key"),
        ("github_token",       "GitHub token"),
        ("aws_access_key",     "AWS key"),
        ("generic_credential", "Generic credential"),
    ]),
    ("Financial", [
        ("credit_card", "Credit card"),
    ]),
    ("Network", [
        ("url_credentials", "URL credentials"),
        ("ipv4",            "IPv4 address"),
    ]),
]

_DIFF_TAG_MASKED = "masked_span"


class DataScrubApp(ctk.CTk):
    """Main application window."""

    def __init__(self, extra_patterns: Sequence[Pattern] = ()) -> None:
        super().__init__()
        self._extra_patterns: list[Pattern] = list(extra_patterns)
        self._custom_patterns: list[Pattern] = []
        self._last_result: ScrubResult | None = None
        self._file_format: str = "text"
        self._current_file: str = ""
        self._scrub_job: int | None = None
        self._allowlist: set[str] = set()
        self._token_map: dict[str, str] = {}

        self.title("datascrub")
        self.geometry("1260x820")
        self.minsize(960, 640)

        self._build_layout()
        self._bind_keys()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self) -> None:
        self.destroy()
        sys.exit(0)

    # ── Layout ─────────────────────────────────────────────────────────────────

    def _build_layout(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        self._build_sidebar()
        self._build_main_area()
        self._build_statusbar()

    # ── Sidebar ────────────────────────────────────────────────────────────────

    def _build_sidebar(self) -> None:
        outer = ctk.CTkFrame(self, width=250, corner_radius=0)
        outer.grid(row=0, column=0, rowspan=2, sticky="nsew")
        outer.grid_propagate(False)
        outer.grid_columnconfigure(0, weight=1)
        outer.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(
            outer, text="datascrub",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).grid(row=0, column=0, pady=(16, 8))
        scroll = ctk.CTkScrollableFrame(outer, corner_radius=0, fg_color="transparent")
        scroll.grid(row=1, column=0, sticky="nsew")
        scroll.grid_columnconfigure(0, weight=1)
        self._build_sidebar_content(scroll)

    def _section(self, parent, text: str, row: int):
        lbl = ctk.CTkLabel(
            parent, text=text,
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="gray60",
        )
        lbl.grid(row=row, column=0, padx=16, pady=(16, 4), sticky="w")
        return lbl, row + 1

    def _build_sidebar_content(self, parent: ctk.CTkScrollableFrame) -> None:
        row = 0

        # ── PROFILE ───────────────────────────────────────────────────────────
        _, row = self._section(parent, "PROFILE", row)
        profile_frame = ctk.CTkFrame(parent, fg_color="transparent")
        profile_frame.grid(row=row, column=0, padx=12, pady=(2, 4), sticky="ew")
        profile_frame.grid_columnconfigure(0, weight=1)
        row += 1
        self._profile_names = [p.name for p in list_profiles()]
        self._profile_var = tk.StringVar(value="(none)")
        self._profile_menu = ctk.CTkOptionMenu(
            profile_frame,
            values=["(none)"] + self._profile_names,
            variable=self._profile_var,
            command=self._on_profile_select,
            width=160, height=28, font=ctk.CTkFont(size=12),
        )
        self._profile_menu.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(
            profile_frame, text="Save\u2026", width=56, height=28,
            font=ctk.CTkFont(size=11), fg_color="gray30", hover_color="gray25",
            command=self._save_profile_dialog,
        ).grid(row=0, column=1, padx=(4, 0))

        # ── MASKING STYLE ─────────────────────────────────────────────────────
        _, row = self._section(parent, "MASKING STYLE", row)
        self._mask_style_var = tk.StringVar(value="partial")
        for value, label in _MASK_STYLES:
            ctk.CTkRadioButton(
                parent, text=label, value=value,
                variable=self._mask_style_var,
                font=ctk.CTkFont(size=12),
                radiobutton_width=16, radiobutton_height=16,
                command=self._on_style_change,
            ).grid(row=row, column=0, padx=20, pady=2, sticky="w")
            row += 1

        # ── MASK CHARACTER ────────────────────────────────────────────────────
        self._mask_char_header, row = self._section(parent, "MASK CHARACTER", row)
        self._mask_char_var = tk.StringVar(value="*")
        preset_frame = ctk.CTkFrame(parent, fg_color="transparent")
        preset_frame.grid(row=row, column=0, padx=16, sticky="w")
        self._preset_frame = preset_frame
        for label, value in _MASK_PRESETS:
            ctk.CTkRadioButton(
                preset_frame, text=label, value=value,
                variable=self._mask_char_var,
                font=ctk.CTkFont(size=13),
                radiobutton_width=16, radiobutton_height=16,
                command=self._on_setting_change,
            ).pack(side="left", padx=(0, 8))
        row += 1
        custom_frame = ctk.CTkFrame(parent, fg_color="transparent")
        custom_frame.grid(row=row, column=0, padx=16, pady=(4, 0), sticky="w")
        self._custom_frame = custom_frame
        ctk.CTkRadioButton(
            custom_frame, text="custom:", value="__custom__",
            variable=self._mask_char_var,
            font=ctk.CTkFont(size=12),
            radiobutton_width=16, radiobutton_height=16,
            command=self._on_setting_change,
        ).pack(side="left")
        self._custom_mask_entry = ctk.CTkEntry(
            custom_frame, width=50, height=26,
            font=ctk.CTkFont(size=13), placeholder_text="?",
        )
        self._custom_mask_entry.pack(side="left", padx=(6, 0))
        self._custom_mask_entry.bind("<KeyRelease>", lambda _: self._on_setting_change())
        row += 1

        # ── PATTERNS ──────────────────────────────────────────────────────────
        _, row = self._section(parent, "PATTERNS", row)
        self._pattern_vars: dict[str, ctk.BooleanVar] = {}
        for group_label, patterns in _PATTERN_GROUPS:
            grp_frame = ctk.CTkFrame(parent, fg_color="transparent")
            grp_frame.grid(row=row, column=0, padx=12, pady=(8, 2), sticky="ew")
            grp_frame.grid_columnconfigure(0, weight=1)
            row += 1
            ctk.CTkLabel(
                grp_frame, text=group_label.upper(),
                font=ctk.CTkFont(size=10, weight="bold"), text_color="gray50",
            ).grid(row=0, column=0, sticky="w")
            tog = ctk.CTkFrame(grp_frame, fg_color="transparent")
            tog.grid(row=0, column=1, sticky="e")
            ctk.CTkButton(
                tog, text="All", width=28, height=18,
                font=ctk.CTkFont(size=9), fg_color="gray35", hover_color="gray28",
                command=lambda p=patterns: self._set_group(p, True),
            ).pack(side="left", padx=(0, 2))
            ctk.CTkButton(
                tog, text="None", width=34, height=18,
                font=ctk.CTkFont(size=9), fg_color="gray35", hover_color="gray28",
                command=lambda p=patterns: self._set_group(p, False),
            ).pack(side="left")
            for name, label in patterns:
                var = ctk.BooleanVar(value=True)
                self._pattern_vars[name] = var
                ctk.CTkCheckBox(
                    parent, text=label, variable=var,
                    font=ctk.CTkFont(size=12),
                    checkbox_width=16, checkbox_height=16,
                    command=self._on_setting_change,
                ).grid(row=row, column=0, padx=24, pady=1, sticky="w")
                row += 1

        # ── ACTIONS ───────────────────────────────────────────────────────────
        _, row = self._section(parent, "ACTIONS", row)
        btn_cfg = dict(width=218, height=34, font=ctk.CTkFont(size=13))
        for text, cmd, fc, hc, tc in [
            ("Open file\u2026  (Ctrl+O)", self._open_file, None, None, None),
            ("Copy output", self._copy, "gray30", "gray25", None),
            ("Save output\u2026  (Ctrl+S)", self._save, "gray30", "gray25", None),
            ("Export / Report\u2026", self._show_export_dialog, "gray30", "gray25", None),
            ("Allowlist\u2026", self._show_allowlist, "gray30", "gray25", None),
            ("Custom patterns\u2026", self._show_pattern_editor, "gray30", "gray25", None),
            ("Clear", self._clear, "gray22", "gray18", "gray60"),
        ]:
            kw = dict(btn_cfg)
            if fc:
                kw["fg_color"] = fc
                kw["hover_color"] = hc
            if tc:
                kw["text_color"] = tc
            ctk.CTkButton(parent, text=text, command=cmd, **kw).grid(
                row=row, column=0, padx=16, pady=3)
            row += 1

        # trailing spacer so the scrollable frame doesn't clip this section
        ctk.CTkLabel(parent, text="", height=20).grid(row=row, column=0)
        row += 1

    # ── Main area (notebook) ───────────────────────────────────────────────────

    def _build_main_area(self) -> None:
        self._notebook = ctk.CTkTabview(self, corner_radius=6)
        self._notebook.grid(row=0, column=1, sticky="nsew", padx=(8, 8), pady=(8, 4))
        for tab_name in ("Editor", "Findings", "Batch"):
            self._notebook.add(tab_name)
        self._build_tab_editor(self._notebook.tab("Editor"))
        self._build_tab_findings(self._notebook.tab("Findings"))
        self._build_tab_batch(self._notebook.tab("Batch"))

    # ── Editor tab ─────────────────────────────────────────────────────────────

    def _build_tab_editor(self, tab) -> None:
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_columnconfigure(1, weight=0)
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_rowconfigure(3, weight=1)
        ctk.CTkLabel(
            tab, text="INPUT",
            font=ctk.CTkFont(size=11, weight="bold"), text_color="gray60",
        ).grid(row=0, column=0, sticky="w", padx=4, pady=(0, 2))
        self._input_box = ctk.CTkTextbox(
            tab, font=ctk.CTkFont(family="monospace", size=12),
            wrap="none", border_width=1,
        )
        self._input_box.grid(row=1, column=0, columnspan=2, sticky="nsew")
        self._input_box.bind("<KeyRelease>", self._on_input_change)
        self._input_box.bind("<<Paste>>", lambda _: self.after(10, self._on_input_change))
        self._output_label = ctk.CTkLabel(
            tab, text="OUTPUT  (masked)",
            font=ctk.CTkFont(size=11, weight="bold"), text_color="gray60",
        )
        self._output_label.grid(row=2, column=0, sticky="w", padx=4, pady=(8, 2))
        self._output_box = tk.Text(
            tab, font=("monospace", 12), wrap="none",
            background="#1e1e1e", foreground="#d4d4d4",
            insertbackground="white", selectbackground="#264f78",
            relief="flat", state="disabled",
        )
        self._output_box.tag_configure(
            _DIFF_TAG_MASKED,
            background="#5a1a1a", foreground="#ff8080",
            font=("monospace", 12, "bold"),
        )
        self._output_box.grid(row=3, column=0, sticky="nsew")
        out_vsb = ttk.Scrollbar(tab, orient="vertical", command=self._output_box.yview)
        out_hsb = ttk.Scrollbar(tab, orient="horizontal", command=self._output_box.xview)
        self._output_box.configure(yscrollcommand=out_vsb.set, xscrollcommand=out_hsb.set)
        out_vsb.grid(row=3, column=1, sticky="ns")
        out_hsb.grid(row=4, column=0, columnspan=2, sticky="ew")

    # ── Findings tab ───────────────────────────────────────────────────────────

    def _build_tab_findings(self, tab) -> None:
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        self._findings_label = ctk.CTkLabel(
            tab, text="FINDINGS  \u2014  none",
            font=ctk.CTkFont(size=11, weight="bold"), text_color="gray60",
        )
        self._findings_label.grid(row=0, column=0, sticky="w", padx=4, pady=(0, 4))
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Findings.Treeview",
            background="#2b2b2b", foreground="white",
            rowheight=22, fieldbackground="#2b2b2b",
            borderwidth=0, font=("monospace", 11),
        )
        style.configure(
            "Findings.Treeview.Heading",
            background="#1e1e1e", foreground="#888888",
            relief="flat", font=("monospace", 11, "bold"),
        )
        style.map("Findings.Treeview",
                  background=[("selected", "#1f6aa5")],
                  foreground=[("selected", "white")])
        cols = ("pattern", "category", "confidence", "original", "masked")
        self._tree = ttk.Treeview(
            tab, columns=cols, show="headings",
            style="Findings.Treeview", height=8,
        )
        for col, heading, width in [
            ("pattern",    "Pattern",    140),
            ("category",   "Category",   100),
            ("confidence", "Conf",        56),
            ("original",   "Original",   270),
            ("masked",     "Masked",     270),
        ]:
            self._tree.heading(col, text=heading)
            self._tree.column(col, width=width, anchor="w")
        self._tree.tag_configure("odd",      background="#252525")
        self._tree.tag_configure("even",     background="#2b2b2b")
        self._tree.tag_configure("low_conf", foreground="#d4a060")
        self._tree.grid(row=1, column=0, sticky="nsew", pady=(0, 4))
        sb = ttk.Scrollbar(tab, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        sb.grid(row=1, column=1, sticky="ns")
        tab.grid_columnconfigure(1, weight=0)
        self._tree.bind("<Button-3>", self._on_finding_right_click)

    # ── Batch tab ──────────────────────────────────────────────────────────────

    def _build_tab_batch(self, tab) -> None:
        tab.grid_columnconfigure(1, weight=1)
        lbl = dict(font=ctk.CTkFont(size=12), anchor="e")
        entry_w = 400
        ctk.CTkLabel(tab, text="Source folder:", **lbl).grid(
            row=0, column=0, padx=(8, 6), pady=(12, 6), sticky="e")
        self._batch_src_var = tk.StringVar()
        ctk.CTkEntry(tab, textvariable=self._batch_src_var, width=entry_w).grid(
            row=0, column=1, pady=(12, 6), sticky="ew")
        ctk.CTkButton(tab, text="Browse\u2026", width=80,
                      command=self._browse_batch_src).grid(
            row=0, column=2, padx=(6, 8), pady=(12, 6))
        ctk.CTkLabel(tab, text="Output folder:", **lbl).grid(
            row=1, column=0, padx=(8, 6), pady=6, sticky="e")
        self._batch_dst_var = tk.StringVar()
        ctk.CTkEntry(tab, textvariable=self._batch_dst_var, width=entry_w).grid(
            row=1, column=1, pady=6, sticky="ew")
        ctk.CTkButton(tab, text="Browse\u2026", width=80,
                      command=self._browse_batch_dst).grid(
            row=1, column=2, padx=(6, 8), pady=6)
        ctk.CTkLabel(tab, text="Audit log (optional):", **lbl).grid(
            row=2, column=0, padx=(8, 6), pady=6, sticky="e")
        self._batch_audit_var = tk.StringVar()
        ctk.CTkEntry(tab, textvariable=self._batch_audit_var, width=entry_w,
                     placeholder_text="e.g. report.json").grid(
            row=2, column=1, pady=6, sticky="ew")
        ctk.CTkButton(tab, text="Browse\u2026", width=80,
                      command=self._browse_batch_audit).grid(
            row=2, column=2, padx=(6, 8), pady=6)
        self._batch_progress = ctk.CTkLabel(
            tab, text="", font=ctk.CTkFont(size=12), text_color="gray60")
        self._batch_progress.grid(row=3, column=0, columnspan=3, pady=(12, 4))
        self._batch_btn = ctk.CTkButton(
            tab, text="Start Batch Scrub", height=36,
            font=ctk.CTkFont(size=13), command=self._run_batch)
        self._batch_btn.grid(row=4, column=0, columnspan=3, pady=(4, 12))
        tab.grid_rowconfigure(5, weight=1)
        self._batch_log = ctk.CTkTextbox(
            tab, height=200, font=ctk.CTkFont(family="monospace", size=11),
            state="disabled")
        self._batch_log.grid(row=5, column=0, columnspan=3, sticky="nsew",
                             padx=8, pady=(0, 8))

    # ── Status bar ─────────────────────────────────────────────────────────────

    def _build_statusbar(self) -> None:
        bar = ctk.CTkFrame(self, height=28, corner_radius=0, fg_color="#1a1a1a")
        bar.grid(row=1, column=0, columnspan=2, sticky="ew")
        bar.grid_columnconfigure(4, weight=1)
        bar.grid_propagate(False)
        lbl_cfg = dict(font=ctk.CTkFont(size=11), text_color="gray55", height=28)
        sep_cfg = dict(font=ctk.CTkFont(size=11), text_color="gray35", height=28)
        self._status_format = ctk.CTkLabel(bar, text="Format: text", **lbl_cfg)
        self._status_format.grid(row=0, column=0, padx=(12, 0), sticky="w")
        ctk.CTkLabel(bar, text="\u2502", **sep_cfg).grid(row=0, column=1, padx=8)
        self._status_chars = ctk.CTkLabel(bar, text="0 chars", **lbl_cfg)
        self._status_chars.grid(row=0, column=2, sticky="w")
        ctk.CTkLabel(bar, text="\u2502", **sep_cfg).grid(row=0, column=3, padx=8)
        self._status_findings = ctk.CTkLabel(bar, text="0 findings", **lbl_cfg)
        self._status_findings.grid(row=0, column=4, sticky="w")
        ctk.CTkLabel(bar, text=f"v{_VERSION}", **lbl_cfg).grid(
            row=0, column=5, padx=(0, 12), sticky="e")

    # ── Key bindings ───────────────────────────────────────────────────────────

    def _bind_keys(self) -> None:
        self.bind("<Control-o>", lambda _: self._open_file())
        self.bind("<Control-s>", lambda _: self._save())

    # ── Event handlers ─────────────────────────────────────────────────────────

    def _on_input_change(self, _event=None) -> None:
        n = len(self._input_box.get("1.0", "end-1c"))
        self._status_chars.configure(text=f"{n:,} chars")
        self._schedule_scrub()

    def _on_style_change(self) -> None:
        style = self._mask_style_var.get()
        needs_char = style in ("partial", "full")
        state = "normal" if needs_char else "disabled"
        self._mask_char_header.configure(text_color="gray60" if needs_char else "gray35")
        for widget in self._preset_frame.winfo_children():
            try:
                widget.configure(state=state)
            except tk.TclError:
                # Fix 9: only ignore Tcl errors (e.g. widget doesn't support
                # the state option); let unexpected Python exceptions propagate.
                pass
        for widget in self._custom_frame.winfo_children():
            try:
                widget.configure(state=state)
            except tk.TclError:
                pass
        self._on_setting_change()

    def _on_setting_change(self) -> None:
        self._scrub()

    def _on_profile_select(self, name: str) -> None:
        if name == "(none)":
            return
        profile = get_profile(name)
        if not profile:
            return
        self._mask_style_var.set(profile.mask_style)
        preset_vals = {v for _, v in _MASK_PRESETS}
        if profile.mask_char in preset_vals:
            self._mask_char_var.set(profile.mask_char)
        else:
            self._mask_char_var.set("__custom__")
            self._custom_mask_entry.delete(0, "end")
            self._custom_mask_entry.insert(0, profile.mask_char)
        disabled = set(profile.disabled_patterns)
        for pname, var in self._pattern_vars.items():
            var.set(pname not in disabled)
        self._allowlist = set(profile.allowlist)
        self._on_style_change()

    def _schedule_scrub(self) -> None:
        if self._scrub_job:
            self.after_cancel(self._scrub_job)
        self._scrub_job = self.after(300, self._scrub)

    def _set_group(self, patterns: list[tuple[str, str]], enabled: bool) -> None:
        for name, _ in patterns:
            if name in self._pattern_vars:
                self._pattern_vars[name].set(enabled)
        self._scrub()

    def _on_finding_right_click(self, event) -> None:
        item = self._tree.identify_row(event.y)
        if not item:
            return
        values = self._tree.item(item, "values")
        if not values:
            return
        original = values[3]
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(
            label=f"Add to allowlist: {original[:40]}",
            command=lambda: self._add_to_allowlist(original),
        )
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.destroy()

    def _add_to_allowlist(self, value: str) -> None:
        self._allowlist.add(value)
        self._scrub()
        self._show_toast(f"Allowlisted: {value[:30]}")

    # ── File actions ────────────────────────────────────────────────────────────

    def _open_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Open file to scrub",
            filetypes=[
                ("All supported", "*.txt *.json *.csv *.log *.md *.yaml *.yml *.env"),
                ("Text files",    "*.txt *.log *.md"),
                ("JSON files",    "*.json"),
                ("CSV files",     "*.csv"),
                ("All files",     "*.*"),
            ],
        )
        if not path:
            return
        try:
            # Fix 1: use errors="replace" so non-UTF-8 files don't raise
            # UnicodeDecodeError — replacement characters are visible in the UI.
            content = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            messagebox.showerror("datascrub", f"Cannot read file:\n{exc}")
            return
        suffix = Path(path).suffix.lower()
        self._file_format = {".json": "json", ".csv": "csv"}.get(suffix, "text")
        self._current_file = Path(path).name
        self._token_map = {}
        self._set_input(content)
        self.title(f"datascrub \u2014 {self._current_file}")
        self._update_status_format()

    def _scrub(self) -> None:
        # Fix 5: run the scrub in a daemon thread so the UI stays responsive
        # for large inputs.  All GUI mutations are dispatched back to the main
        # thread via self.after().
        self._scrub_job = None
        text = self._input_box.get("1.0", "end-1c")
        disabled = frozenset(n for n, v in self._pattern_vars.items() if not v.get())
        mask_char = self._resolve_mask_char()
        mask_style = self._mask_style_var.get()
        if mask_style != "token":
            self._token_map = {}
        all_patterns = self._extra_patterns + self._custom_patterns
        kwargs = dict(
            categories=None,
            extra_patterns=all_patterns,
            mask_char=mask_char,
            mask_style=mask_style,
            disabled_patterns=disabled,
            allowlist=frozenset(self._allowlist),
            token_map=self._token_map,
        )
        file_format = self._file_format

        def _worker():
            if file_format == "json":
                result = scrub_json(text, **kwargs)
            elif file_format == "csv":
                result = scrub_csv(text, **kwargs)
            else:
                result = scrub(text, **kwargs)
            self.after(0, lambda: self._apply_scrub_result(result, text, file_format))

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_scrub_result(
        self, result: ScrubResult, text: str, file_format: str
    ) -> None:
        """Apply a completed scrub result to the UI (must run on the main thread)."""
        self._last_result = result

        # Output — with diff highlighting for plain text
        self._output_box.configure(state="normal")
        self._output_box.delete("1.0", "end")
        if file_format == "text" and result.findings:
            pos = 0
            for f in result.findings:
                if f.start < pos:
                    continue
                if f.start > pos:
                    self._output_box.insert("end", text[pos:f.start])
                self._output_box.insert("end", f.masked, _DIFF_TAG_MASKED)
                pos = f.end
            if pos < len(text):
                self._output_box.insert("end", text[pos:])
        else:
            self._output_box.insert("end", result.text)
        self._output_box.configure(state="disabled")

        # Findings table
        self._tree.delete(*self._tree.get_children())
        for idx, f in enumerate(result.findings):
            orig = f.original if len(f.original) <= 44 else f.original[:41] + "\u2026"
            conf_str = f"{f.confidence * 100:.0f}%"
            tag = "odd" if idx % 2 else "even"
            tags = (tag,) if f.confidence >= 0.9 else (tag, "low_conf")
            self._tree.insert("", "end", values=(
                f.pattern_name, f.category, conf_str, orig, f.masked,
            ), tags=tags)

        count = result.finding_count
        self._findings_label.configure(
            text=f"FINDINGS  \u2014  {count} detected" if count else "FINDINGS  \u2014  none")
        self._output_label.configure(
            text=f"OUTPUT  (masked \u2014 {count} replacement{'s' if count != 1 else ''})"
            if count else "OUTPUT  (no sensitive data found)")
        self._status_findings.configure(
            text=f"{count} finding{'s' if count != 1 else ''}")

    # ── Output actions ──────────────────────────────────────────────────────────

    def _copy(self) -> None:
        if self._last_result is None:
            messagebox.showinfo("datascrub", "Nothing to copy yet.")
            return
        self.clipboard_clear()
        self.clipboard_append(self._last_result.text)
        self._show_toast("Copied to clipboard")

    def _save(self) -> None:
        if self._last_result is None:
            messagebox.showinfo("datascrub", "Nothing to save yet.")
            return
        path = filedialog.asksaveasfilename(
            title="Save masked output",
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("JSON", "*.json"),
                       ("CSV", "*.csv"), ("All", "*.*")],
        )
        if not path:
            return
        try:
            Path(path).write_text(self._last_result.text, encoding="utf-8")
            self._show_toast(f"Saved  {Path(path).name}")
        except OSError as exc:
            messagebox.showerror("datascrub", f"Cannot save:\n{exc}")

    def _export_audit(self, fmt: str = "json") -> None:
        if self._last_result is None:
            messagebox.showinfo("datascrub", "Nothing to export yet.")
            return
        if fmt == "csv":
            ft = [("CSV", "*.csv"), ("All", "*.*")]
            ext = ".csv"
        else:
            ft = [("JSON", "*.json"), ("All", "*.*")]
            ext = ".json"
        path = filedialog.asksaveasfilename(
            title="Export audit log",
            defaultextension=ext,
            filetypes=ft,
        )
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
            messagebox.showerror("datascrub", f"Cannot save:\n{exc}")

    def _show_report(self) -> None:
        if self._last_result is None:
            messagebox.showinfo("datascrub", "Nothing to report yet.")
            return
        source = self._current_file or "input"
        report = export_text([(source, self._last_result)], include_original=False)
        win = ctk.CTkToplevel(self)
        win.title("De-identification Report")
        win.geometry("640x480")
        win.update_idletasks()
        box = ctk.CTkTextbox(win, font=ctk.CTkFont(family="monospace", size=12))
        box.pack(fill="both", expand=True, padx=8, pady=8)
        box.insert("1.0", report)
        box.configure(state="disabled")

    def _clear(self) -> None:
        self._input_box.delete("1.0", "end")
        self._output_box.configure(state="normal")
        self._output_box.delete("1.0", "end")
        self._output_box.configure(state="disabled")
        self._tree.delete(*self._tree.get_children())
        self._last_result = None
        self._file_format = "text"
        self._current_file = ""
        self._token_map = {}
        self.title("datascrub")
        self._findings_label.configure(text="FINDINGS  \u2014  none")
        self._output_label.configure(text="OUTPUT  (masked)")
        self._status_chars.configure(text="0 chars")
        self._status_findings.configure(text="0 findings")
        self._update_status_format()

    # ── Allowlist dialog ────────────────────────────────────────────────────────

    def _show_allowlist(self) -> None:
        win = ctk.CTkToplevel(self)
        win.title("Allowlist Manager")
        win.geometry("500x420")
        win.update_idletasks()
        win.after(100, win.grab_set)
        ctk.CTkLabel(
            win, text="Values in this list will never be masked:",
            font=ctk.CTkFont(size=12), text_color="gray70",
        ).pack(padx=12, pady=(12, 4), anchor="w")
        lb_frame = ctk.CTkFrame(win)
        lb_frame.pack(fill="both", expand=True, padx=12, pady=4)
        listbox = tk.Listbox(
            lb_frame, bg="#2b2b2b", fg="white", selectbackground="#1f6aa5",
            font=("monospace", 12), relief="flat", bd=0,
        )
        listbox.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(lb_frame, command=listbox.yview)
        listbox.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        for v in sorted(self._allowlist):
            listbox.insert("end", v)

        status_lbl = ctk.CTkLabel(win, text="", font=ctk.CTkFont(size=11),
                                   text_color="gray60")
        status_lbl.pack(pady=(2, 0))

        entry_frame = ctk.CTkFrame(win, fg_color="transparent")
        entry_frame.pack(fill="x", padx=12, pady=(2, 8))
        entry = ctk.CTkEntry(entry_frame, placeholder_text="Add value\u2026")
        entry.pack(side="left", fill="x", expand=True, padx=(0, 6))

        def _add(_event=None):
            val = entry.get().strip()
            if not val:
                return
            if val in self._allowlist:
                status_lbl.configure(text=f"Already in list: {val[:40]}",
                                     text_color="#d4a060")
                return
            self._allowlist.add(val)
            items = listbox.get(0, "end")
            insert_at = next((i for i, v in enumerate(items) if v > val), len(items))
            listbox.insert(insert_at, val)
            entry.delete(0, "end")
            status_lbl.configure(text=f"Added: {val[:40]}", text_color="#60e060")
            self._scrub()

        def _remove():
            sel = listbox.curselection()
            if not sel:
                return
            val = listbox.get(sel[0])
            self._allowlist.discard(val)
            listbox.delete(sel[0])
            status_lbl.configure(text=f"Removed: {val[:40]}", text_color="gray60")
            self._scrub()

        def _clear_all():
            if not self._allowlist:
                return
            self._allowlist.clear()
            listbox.delete(0, "end")
            status_lbl.configure(text="Allowlist cleared.", text_color="gray60")
            self._scrub()

        entry.bind("<Return>", _add)
        ctk.CTkButton(entry_frame, text="Add", width=60, command=_add).pack(side="left")
        ctk.CTkButton(
            entry_frame, text="Remove", width=75,
            fg_color="gray30", hover_color="gray25", command=_remove,
        ).pack(side="left", padx=(6, 0))
        ctk.CTkButton(
            entry_frame, text="Clear all", width=80,
            fg_color="#5a1a1a", hover_color="#6e2020", command=_clear_all,
        ).pack(side="left", padx=(6, 0))
        entry.focus()

    # ── Custom pattern editor ───────────────────────────────────────────────────

    def _show_pattern_editor(self) -> None:
        win = ctk.CTkToplevel(self)
        win.title("Custom Pattern Editor")
        win.geometry("620x580")
        win.update_idletasks()
        win.after(100, win.grab_set)

        # ── Form ──────────────────────────────────────────────────────────────
        form = ctk.CTkFrame(win, fg_color="transparent")
        form.pack(fill="x", padx=12, pady=(12, 4))
        form.grid_columnconfigure(1, weight=1)
        fields = {}
        for i, (lbl, ph) in enumerate([
            ("Name:",     "my_secret"),
            ("Category:", "credentials"),
            ("Regex:",    r"(?i)my_token[=:\s]+([a-zA-Z0-9]{20,})"),
        ]):
            ctk.CTkLabel(form, text=lbl, font=ctk.CTkFont(size=12)).grid(
                row=i, column=0, sticky="e", padx=(0, 8), pady=4)
            e = ctk.CTkEntry(form, placeholder_text=ph)
            e.grid(row=i, column=1, sticky="ew", pady=4)
            fields[lbl] = e

        status_lbl = ctk.CTkLabel(win, text="", font=ctk.CTkFont(size=11),
                                   text_color="gray60")
        status_lbl.pack(pady=(0, 2))

        # ── Test area ─────────────────────────────────────────────────────────
        test_frame = ctk.CTkFrame(win)
        test_frame.pack(fill="x", padx=12, pady=(0, 6))
        test_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(test_frame, text="Test:",
                     font=ctk.CTkFont(size=12)).grid(
            row=0, column=0, sticky="e", padx=(8, 8), pady=6)
        test_entry = ctk.CTkEntry(
            test_frame,
            placeholder_text="Paste sample text here to verify a match…",
        )
        test_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8), pady=6)
        test_result = ctk.CTkLabel(
            test_frame, text="", font=ctk.CTkFont(family="monospace", size=11),
            text_color="gray60", anchor="w",
        )
        test_result.grid(row=1, column=0, columnspan=2, sticky="w",
                         padx=12, pady=(0, 6))

        # Fix 12: run regex test in a background thread with a timeout so that
        # a pathological (ReDoS) pattern cannot freeze the UI.
        _REGEX_TEST_TIMEOUT_S = 2.0
        _test_serial = [0]  # mutable cell to detect stale results

        def _test(_event=None):
            pattern_str = fields["Regex:"].get().strip()
            sample = test_entry.get()
            if not pattern_str:
                test_result.configure(text="Enter a regex first.",
                                      text_color="#d4a060")
                return
            try:
                compiled = re.compile(pattern_str)
            except re.error as e:
                test_result.configure(text=f"Regex error: {e}",
                                      text_color="#e06060")
                return

            _test_serial[0] += 1
            serial = _test_serial[0]
            test_result.configure(text="Testing\u2026", text_color="gray60")

            def _run():
                import queue as _queue
                q: _queue.Queue = _queue.Queue()

                def _match():
                    try:
                        q.put(compiled.findall(sample))
                    except Exception as exc:
                        q.put(exc)

                t = threading.Thread(target=_match, daemon=True)
                t.start()
                t.join(timeout=_REGEX_TEST_TIMEOUT_S)

                if serial != _test_serial[0]:
                    return  # superseded by a later test request

                if t.is_alive():
                    self.after(0, lambda: test_result.configure(
                        text="Timed out — pattern may be too complex (ReDoS risk).",
                        text_color="#e06060",
                    ))
                    return

                result_val = q.get_nowait() if not q.empty() else []
                if isinstance(result_val, Exception):
                    self.after(0, lambda: test_result.configure(
                        text=f"Error: {result_val}", text_color="#e06060"))
                    return

                matches = result_val
                if not matches:
                    self.after(0, lambda: test_result.configure(
                        text="No match.", text_color="#d4a060"))
                else:
                    preview = ", ".join(
                        repr(m if isinstance(m, str) else m[0])
                        for m in matches[:5]
                    )
                    self.after(0, lambda: test_result.configure(
                        text=f"{len(matches)} match(es): {preview}",
                        text_color="#60e060",
                    ))

            threading.Thread(target=_run, daemon=True).start()

        test_entry.bind("<KeyRelease>", _test)
        ctk.CTkButton(test_frame, text="Test", width=70,
                      command=_test).grid(row=0, column=2, padx=(0, 8), pady=6)

        # ── Existing patterns list ────────────────────────────────────────────
        ctk.CTkLabel(win, text="Custom patterns:",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="gray60").pack(anchor="w", padx=14)
        listbox_frame = ctk.CTkFrame(win)
        listbox_frame.pack(fill="both", expand=True, padx=12, pady=(2, 4))
        listbox = tk.Listbox(
            listbox_frame, bg="#2b2b2b", fg="white", selectbackground="#1f6aa5",
            font=("monospace", 11), relief="flat", bd=0,
        )
        listbox.pack(side="left", fill="both", expand=True)
        lb_sb = ttk.Scrollbar(listbox_frame, command=listbox.yview)
        listbox.configure(yscrollcommand=lb_sb.set)
        lb_sb.pack(side="right", fill="y")
        for p in self._custom_patterns:
            listbox.insert("end", f"{p.name}  [{p.category}]  {p.regex.pattern[:50]}")

        def _add(_event=None):
            name = fields["Name:"].get().strip()
            cat = fields["Category:"].get().strip() or "custom"
            pattern_str = fields["Regex:"].get().strip()
            if not name or not pattern_str:
                status_lbl.configure(text="Name and Regex are required.",
                                     text_color="#e06060")
                return
            if any(p.name == name for p in self._custom_patterns):
                status_lbl.configure(text=f"Name already exists: {name}",
                                     text_color="#d4a060")
                return
            try:
                compiled = re.compile(pattern_str)
            except re.error as e:
                status_lbl.configure(text=f"Regex error: {e}", text_color="#e06060")
                return

            def _masker(m: re.Match, _c=compiled) -> str:
                # use first capture group if present and matched, else whole match
                g1 = m.group(1) if _c.groups >= 1 else None
                val = g1 if g1 is not None else m.group(0)
                # return with * so engine can swap in the user's mask_char
                return val[:2] + "*" * max(4, len(val) - 2) if len(val) > 4 else "****"

            p = Pattern(name=name, category=cat, regex=compiled,
                        masker=_masker, confidence=0.9)
            self._custom_patterns.append(p)
            listbox.insert("end", f"{name}  [{cat}]  {pattern_str[:50]}")
            status_lbl.configure(text=f"Added: {name}", text_color="#60e060")
            for f in fields.values():
                f.delete(0, "end")
            self._scrub()

        def _remove():
            sel = listbox.curselection()
            if not sel:
                return
            self._custom_patterns.pop(sel[0])
            listbox.delete(sel[0])
            status_lbl.configure(text="Pattern removed.", text_color="gray60")
            self._scrub()

        fields["Regex:"].bind("<Return>", _add)
        btn_f = ctk.CTkFrame(win, fg_color="transparent")
        btn_f.pack(padx=12, pady=(0, 12))
        ctk.CTkButton(btn_f, text="Add pattern", command=_add).pack(
            side="left", padx=(0, 6))
        ctk.CTkButton(btn_f, text="Remove selected",
                      fg_color="gray30", hover_color="gray25",
                      command=_remove).pack(side="left")
        fields["Name:"].focus()

    # ── Profile save dialog ─────────────────────────────────────────────────────

    def _save_profile_dialog(self) -> None:
        win = ctk.CTkToplevel(self)
        win.title("Save Profile")
        win.geometry("360x200")
        win.update_idletasks()
        win.after(100, win.grab_set)
        ctk.CTkLabel(win, text="Profile name:", font=ctk.CTkFont(size=12)).pack(
            pady=(20, 4))
        entry = ctk.CTkEntry(win, width=280)
        entry.pack()
        status = ctk.CTkLabel(win, text="", font=ctk.CTkFont(size=11),
                               text_color="gray60")
        status.pack(pady=4)

        def _save():
            name = entry.get().strip()
            if not name:
                return
            disabled = [n for n, v in self._pattern_vars.items() if not v.get()]
            p = Profile(
                name=name,
                mask_style=self._mask_style_var.get(),
                mask_char=self._resolve_mask_char(),
                disabled_patterns=disabled,
                allowlist=list(self._allowlist),
            )
            try:
                save_profile(p)
            except FileExistsError as exc:
                # Fix 3 (GUI): surface filename-collision error to the user.
                status.configure(text=str(exc), text_color="#e06060")
                return
            self._profile_names = [pr.name for pr in list_profiles()]
            self._profile_menu.configure(values=["(none)"] + self._profile_names)
            self._profile_var.set(name)
            status.configure(text=f"Saved: {name}", text_color="#60e060")
            win.after(1200, win.destroy)

        ctk.CTkButton(win, text="Save", command=_save).pack(pady=8)

    # ── Batch scrub ─────────────────────────────────────────────────────────────

    def _browse_batch_src(self) -> None:
        d = filedialog.askdirectory(title="Select source folder")
        if d:
            self._batch_src_var.set(d)

    def _browse_batch_dst(self) -> None:
        d = filedialog.askdirectory(title="Select output folder")
        if d:
            self._batch_dst_var.set(d)

    def _browse_batch_audit(self) -> None:
        p = filedialog.asksaveasfilename(
            title="Audit log path", defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv")])
        if p:
            self._batch_audit_var.set(p)

    def _batch_log_line(self, line: str) -> None:
        self._batch_log.configure(state="normal")
        self._batch_log.insert("end", line + "\n")
        self._batch_log.see("end")
        self._batch_log.configure(state="disabled")

    def _run_batch(self) -> None:
        src = self._batch_src_var.get().strip()
        dst = self._batch_dst_var.get().strip()
        if not src or not dst:
            messagebox.showwarning("datascrub", "Set source and output folders first.")
            return
        src_path = Path(src)
        dst_path = Path(dst)
        if not src_path.is_dir():
            messagebox.showerror("datascrub", "Source folder not found.")
            return
        self._batch_btn.configure(state="disabled", text="Running\u2026")
        self._batch_log.configure(state="normal")
        self._batch_log.delete("1.0", "end")
        self._batch_log.configure(state="disabled")
        disabled = frozenset(n for n, v in self._pattern_vars.items() if not v.get())
        mask_char = self._resolve_mask_char()
        mask_style = self._mask_style_var.get()
        audit_path_str = self._batch_audit_var.get().strip()
        allowlist = frozenset(self._allowlist)
        all_patterns = self._extra_patterns + self._custom_patterns

        def _worker():
            exts = {".txt", ".json", ".csv", ".log", ".yaml", ".yml", ".xml", ".md"}
            paths = [p for p in src_path.rglob("*")
                     if p.is_file() and p.suffix.lower() in exts]
            if not paths:
                self.after(0, lambda: self._batch_log_line("No supported files found."))
                self.after(0, lambda: self._batch_btn.configure(
                    state="normal", text="Start Batch Scrub"))
                return
            all_results = []
            token_map: dict = {}
            total = 0
            for path in sorted(paths):
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                    fmt = {".json": "json", ".csv": "csv"}.get(
                        path.suffix.lower(), "text")
                    kw = dict(extra_patterns=all_patterns, mask_char=mask_char,
                              mask_style=mask_style, disabled_patterns=disabled,
                              allowlist=allowlist, token_map=token_map)
                    if fmt == "json":
                        result = scrub_json(text, **kw)
                    elif fmt == "csv":
                        result = scrub_csv(text, **kw)
                    else:
                        result = scrub(text, **kw)
                    rel = path.relative_to(src_path)
                    out = dst_path / rel
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_text(result.text, encoding="utf-8")
                    total += result.finding_count
                    all_results.append((str(path), result))
                    msg = f"  \u2713  {rel}  ({result.finding_count} findings)"
                except Exception as e:
                    msg = f"  \u2717  {path.name}: {e}"
                self.after(0, lambda m=msg: self._batch_log_line(m))
            summary = f"\nDone: {len(all_results)} files, {total} findings masked."
            self.after(0, lambda: self._batch_log_line(summary))
            if audit_path_str and all_results:
                try:
                    ap = Path(audit_path_str)
                    if ap.suffix.lower() == ".csv":
                        audit_csv(all_results, ap)
                    else:
                        audit_json(all_results, ap)
                    self.after(0, lambda: self._batch_log_line(
                        f"Audit log: {audit_path_str}"))
                except Exception as e:
                    self.after(0, lambda e=e: self._batch_log_line(
                        f"Audit error: {e}"))
            self.after(0, lambda: self._batch_btn.configure(
                state="normal", text="Start Batch Scrub"))

        threading.Thread(target=_worker, daemon=True).start()

    def _show_export_dialog(self) -> None:
        if self._last_result is None:
            messagebox.showinfo("datascrub", "Nothing to export yet.")
            return
        win = ctk.CTkToplevel(self)
        win.title("Export / Report")
        win.geometry("300x240")
        win.update_idletasks()
        win.after(100, win.grab_set)
        ctk.CTkLabel(
            win, text="Export options:",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).pack(pady=(20, 12))
        btn_cfg = dict(width=240, height=34, font=ctk.CTkFont(size=12))

        def _do(fn):
            win.destroy()
            fn()

        ctk.CTkButton(
            win, text="Save masked output…",
            command=lambda: _do(self._save), **btn_cfg,
        ).pack(pady=4)
        ctk.CTkButton(
            win, text="Audit log (JSON)…",
            fg_color="gray30", hover_color="gray25",
            command=lambda: _do(lambda: self._export_audit("json")), **btn_cfg,
        ).pack(pady=4)
        ctk.CTkButton(
            win, text="Audit log (CSV)…",
            fg_color="gray30", hover_color="gray25",
            command=lambda: _do(lambda: self._export_audit("csv")), **btn_cfg,
        ).pack(pady=4)
        ctk.CTkButton(
            win, text="View report",
            fg_color="gray30", hover_color="gray25",
            command=lambda: _do(self._show_report), **btn_cfg,
        ).pack(pady=4)

    # ── Helpers ─────────────────────────────────────────────────────────────────

    def _resolve_mask_char(self) -> str:
        val = self._mask_char_var.get()
        if val == "__custom__":
            custom = self._custom_mask_entry.get()
            return custom[0] if custom else "*"
        return val

    def _set_input(self, text: str) -> None:
        self._input_box.delete("1.0", "end")
        self._input_box.insert("1.0", text)
        self._on_input_change()

    def _update_status_format(self) -> None:
        label = {"json": "Format: JSON", "csv": "Format: CSV"}.get(
            self._file_format, "Format: text")
        if self._current_file:
            label += f"  \u00b7  {self._current_file}"
        self._status_format.configure(text=label)

    def _show_toast(self, message: str) -> None:
        original = self.title()
        self.title(f"datascrub \u2014 {message}")
        self.after(2500, lambda: self.title(original))
