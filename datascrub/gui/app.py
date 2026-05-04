"""
CustomTkinter GUI for datascrub.

Layout
------
┌─────────────────────────────────────────────────────────────────┐
│  datascrub                                                      │
├──────────────────────┬──────────────────────────────────────────┤
│  CATEGORIES  All None│  ┌─ Input ────────────────── 0 chars ──┐ │
│  ☑ PII               │  │                                     │ │
│  ☑ Credentials       │  └─────────────────────────────────────┘ │
│  ☑ Financial         │  ┌─ Output (masked) ───────────────────┐ │
│  ☑ Network           │  │                                     │ │
│                      │  └─────────────────────────────────────┘ │
│  MASK CHARACTER      ├──────────────────────────────────────────┤
│  ● *  ○ █  ○ X  ○ #  │  FINDINGS — none                        │
│  ○ custom: [___]     │  Pattern  Category  Original  Masked    │
│                      │                                          │
│  ACTIONS             │                                          │
│  [ Open file…  ]     │                                          │
│  [    Scrub    ]     │                                          │
│  [ Copy output ]     │                                          │
│  [ Save output ]     │                                          │
│  [    Clear    ]     │                                          │
├──────────────────────┴──────────────────────────────────────────┤
│  Format: text  │  0 chars  │  0 findings              v1.0.0   │
└─────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from typing import Sequence

import customtkinter as ctk

from ..engine import scrub, ScrubResult
from ..handlers import scrub_json, scrub_csv
from ..patterns import Pattern

# ── Theme ──────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

_VERSION = "1.0.0"

# Masking styles
_MASK_STYLES = [
    ("partial",  "Partial  (a***@b.com)"),
    ("label",    "Type label  ([EMAIL])"),
    ("full",     "Full block  (*****)"),
    ("redacted", "Redacted  ([REDACTED])"),
]

# Preset mask characters (shown only for partial/full styles)
_MASK_PRESETS = [("*", "*"), ("█", "█"), ("X", "X"), ("#", "#")]

# Per-pattern groups: (pattern_name, display_label)
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


class DataScrubApp(ctk.CTk):
    """Main application window."""

    def __init__(self, extra_patterns: Sequence[Pattern] = ()) -> None:
        super().__init__()
        self._extra_patterns = list(extra_patterns)
        self._last_result: ScrubResult | None = None
        self._file_format: str = "text"
        self._current_file: str = ""
        self._scrub_job: str | None = None

        self.title("datascrub")
        self.geometry("1160x760")
        self.minsize(900, 600)

        self._build_layout()
        self._bind_keys()

    # ── Layout ─────────────────────────────────────────────────────────────────

    def _build_layout(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=3)
        self.grid_rowconfigure(1, weight=2)
        self.grid_rowconfigure(2, weight=0)

        self._build_sidebar()
        self._build_editor()
        self._build_findings()
        self._build_statusbar()

    # ── Sidebar ────────────────────────────────────────────────────────────────

    def _build_sidebar(self) -> None:
        # Outer fixed-width frame
        outer = ctk.CTkFrame(self, width=240, corner_radius=0)
        outer.grid(row=0, column=0, rowspan=2, sticky="nsew")
        outer.grid_propagate(False)
        outer.grid_columnconfigure(0, weight=1)
        outer.grid_rowconfigure(1, weight=1)

        # Title (outside scroll area so it stays pinned)
        ctk.CTkLabel(
            outer, text="datascrub",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).grid(row=0, column=0, pady=(16, 8))

        # Scrollable content area
        scroll = ctk.CTkScrollableFrame(outer, corner_radius=0, fg_color="transparent")
        scroll.grid(row=1, column=0, sticky="nsew")
        scroll.grid_columnconfigure(0, weight=1)

        self._build_sidebar_content(scroll)

    def _build_sidebar_content(self, parent: ctk.CTkScrollableFrame) -> None:
        row = 0

        # ── MASKING STYLE ──────────────────────────────────────────────────────
        ctk.CTkLabel(
            parent, text="MASKING STYLE",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="gray60",
        ).grid(row=row, column=0, padx=16, pady=(4, 4), sticky="w")
        row += 1

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

        # ── MASK CHARACTER ─────────────────────────────────────────────────────
        self._mask_char_header = ctk.CTkLabel(
            parent, text="MASK CHARACTER",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="gray60",
        )
        self._mask_char_header.grid(row=row, column=0, padx=16, pady=(14, 4), sticky="w")
        row += 1

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
            font=ctk.CTkFont(size=13),
            placeholder_text="?",
        )
        self._custom_mask_entry.pack(side="left", padx=(6, 0))
        self._custom_mask_entry.bind("<KeyRelease>", lambda _: self._on_setting_change())
        row += 1

        # ── PATTERNS ───────────────────────────────────────────────────────────
        ctk.CTkLabel(
            parent, text="PATTERNS",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="gray60",
        ).grid(row=row, column=0, padx=16, pady=(16, 2), sticky="w")
        row += 1

        self._pattern_vars: dict[str, ctk.BooleanVar] = {}

        for group_label, patterns in _PATTERN_GROUPS:
            # Group header with All/None toggles
            grp_frame = ctk.CTkFrame(parent, fg_color="transparent")
            grp_frame.grid(row=row, column=0, padx=12, pady=(8, 2), sticky="ew")
            grp_frame.grid_columnconfigure(0, weight=1)
            row += 1

            ctk.CTkLabel(
                grp_frame, text=group_label.upper(),
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color="gray50",
            ).grid(row=0, column=0, sticky="w")

            tog = ctk.CTkFrame(grp_frame, fg_color="transparent")
            tog.grid(row=0, column=1, sticky="e")
            ctk.CTkButton(
                tog, text="All", width=28, height=18,
                font=ctk.CTkFont(size=9),
                fg_color="gray35", hover_color="gray28",
                command=lambda p=patterns: self._set_group(p, True),
            ).pack(side="left", padx=(0, 2))
            ctk.CTkButton(
                tog, text="None", width=34, height=18,
                font=ctk.CTkFont(size=9),
                fg_color="gray35", hover_color="gray28",
                command=lambda p=patterns: self._set_group(p, False),
            ).pack(side="left")

            for name, label in patterns:
                var = ctk.BooleanVar(value=True)
                self._pattern_vars[name] = var
                ctk.CTkCheckBox(
                    parent, text=label,
                    variable=var,
                    font=ctk.CTkFont(size=12),
                    checkbox_width=16, checkbox_height=16,
                    command=self._on_setting_change,
                ).grid(row=row, column=0, padx=24, pady=1, sticky="w")
                row += 1

        # ── ACTIONS ────────────────────────────────────────────────────────────
        ctk.CTkLabel(
            parent, text="ACTIONS",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="gray60",
        ).grid(row=row, column=0, padx=16, pady=(18, 4), sticky="w")
        row += 1

        btn_cfg = dict(width=208, height=34, font=ctk.CTkFont(size=13))
        ctk.CTkButton(
            parent, text="Open file…  (Ctrl+O)", command=self._open_file,
            **btn_cfg,
        ).grid(row=row, column=0, padx=16, pady=3)
        row += 1
        ctk.CTkButton(
            parent, text="Copy output  (Ctrl+C)", command=self._copy,
            fg_color="gray30", hover_color="gray25",
            **btn_cfg,
        ).grid(row=row, column=0, padx=16, pady=3)
        row += 1
        ctk.CTkButton(
            parent, text="Save output…  (Ctrl+S)", command=self._save,
            fg_color="gray30", hover_color="gray25",
            **btn_cfg,
        ).grid(row=row, column=0, padx=16, pady=3)
        row += 1
        ctk.CTkButton(
            parent, text="Clear", command=self._clear,
            fg_color="gray22", hover_color="gray18",
            text_color="gray60",
            **btn_cfg,
        ).grid(row=row, column=0, padx=16, pady=(3, 16))

    # ── Editor ─────────────────────────────────────────────────────────────────

    def _build_editor(self) -> None:
        editor = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        editor.grid(row=0, column=1, sticky="nsew", padx=(8, 8), pady=(8, 4))
        editor.grid_columnconfigure(0, weight=1)
        editor.grid_rowconfigure(1, weight=1)
        editor.grid_rowconfigure(3, weight=1)

        # Input header
        input_hdr = ctk.CTkFrame(editor, fg_color="transparent")
        input_hdr.grid(row=0, column=0, sticky="ew", padx=4, pady=(0, 2))
        input_hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            input_hdr, text="INPUT",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="gray60",
        ).grid(row=0, column=0, sticky="w")
        self._input_char_label = ctk.CTkLabel(
            input_hdr, text="",
            font=ctk.CTkFont(size=11),
            text_color="gray50",
        )
        self._input_char_label.grid(row=0, column=1, sticky="e")

        self._input_box = ctk.CTkTextbox(
            editor,
            font=ctk.CTkFont(family="monospace", size=12),
            wrap="none",
            border_width=1,
        )
        self._input_box.grid(row=1, column=0, sticky="nsew")
        self._input_box.bind("<KeyRelease>", self._on_input_change)
        self._input_box.bind("<<Paste>>", lambda _: self.after(10, self._on_input_change))

        # Output header
        self._output_label = ctk.CTkLabel(
            editor, text="OUTPUT  (masked)",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="gray60",
        )
        self._output_label.grid(row=2, column=0, sticky="w", padx=4, pady=(8, 2))

        self._output_box = ctk.CTkTextbox(
            editor,
            font=ctk.CTkFont(family="monospace", size=12),
            wrap="none",
            border_width=1,
            state="disabled",
            text_color="gray70",
        )
        self._output_box.grid(row=3, column=0, sticky="nsew")

    # ── Findings table ─────────────────────────────────────────────────────────

    def _build_findings(self) -> None:
        frame = ctk.CTkFrame(self, corner_radius=0)
        frame.grid(row=1, column=1, sticky="nsew", padx=8, pady=(4, 4))
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        self._findings_label = ctk.CTkLabel(
            frame, text="FINDINGS  —  none",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="gray60",
        )
        self._findings_label.grid(row=0, column=0, sticky="w", padx=10, pady=(6, 2))

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

        cols = ("pattern", "category", "original", "masked")
        self._tree = ttk.Treeview(
            frame, columns=cols, show="headings",
            style="Findings.Treeview", height=6,
        )
        for col, heading, width in [
            ("pattern",  "Pattern",  150),
            ("category", "Category", 110),
            ("original", "Original", 280),
            ("masked",   "Masked",   280),
        ]:
            self._tree.heading(col, text=heading)
            self._tree.column(col, width=width, anchor="w")

        self._tree.tag_configure("odd",  background="#252525")
        self._tree.tag_configure("even", background="#2b2b2b")
        self._tree.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))

        sb = ttk.Scrollbar(frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        sb.grid(row=1, column=1, sticky="ns")
        frame.grid_columnconfigure(1, weight=0)

    # ── Status bar ─────────────────────────────────────────────────────────────

    def _build_statusbar(self) -> None:
        bar = ctk.CTkFrame(self, height=28, corner_radius=0, fg_color="#1a1a1a")
        bar.grid(row=2, column=0, columnspan=2, sticky="ew")
        bar.grid_columnconfigure(4, weight=1)
        bar.grid_propagate(False)

        lbl_cfg = dict(font=ctk.CTkFont(size=11), text_color="gray55", height=28)
        sep_cfg = dict(font=ctk.CTkFont(size=11), text_color="gray35", height=28)

        self._status_format = ctk.CTkLabel(bar, text="Format: text", **lbl_cfg)
        self._status_format.grid(row=0, column=0, padx=(12, 0), sticky="w")
        ctk.CTkLabel(bar, text="│", **sep_cfg).grid(row=0, column=1, padx=8)
        self._status_chars = ctk.CTkLabel(bar, text="0 chars", **lbl_cfg)
        self._status_chars.grid(row=0, column=2, sticky="w")
        ctk.CTkLabel(bar, text="│", **sep_cfg).grid(row=0, column=3, padx=8)
        self._status_findings = ctk.CTkLabel(bar, text="0 findings", **lbl_cfg)
        self._status_findings.grid(row=0, column=4, sticky="w")
        ctk.CTkLabel(bar, text=f"v{_VERSION}", **lbl_cfg).grid(
            row=0, column=5, padx=(0, 12), sticky="e"
        )

    # ── Key bindings ───────────────────────────────────────────────────────────

    def _bind_keys(self) -> None:
        self.bind("<Control-o>", lambda _: self._open_file())
        self.bind("<Control-s>", lambda _: self._save())

    # ── Event handlers ─────────────────────────────────────────────────────────

    def _on_input_change(self, _event=None) -> None:
        n = len(self._input_box.get("1.0", "end-1c"))
        self._input_char_label.configure(text=f"{n:,} chars")
        self._status_chars.configure(text=f"{n:,} chars")
        self._schedule_scrub()

    def _on_style_change(self) -> None:
        """Show/hide mask-char picker based on chosen style."""
        style = self._mask_style_var.get()
        needs_char = style in ("partial", "full")
        state = "normal" if needs_char else "disabled"
        # Visually dim when not applicable
        self._mask_char_header.configure(text_color="gray60" if needs_char else "gray35")
        for widget in self._preset_frame.winfo_children():
            try:
                widget.configure(state=state)
            except Exception:
                pass
        for widget in self._custom_frame.winfo_children():
            try:
                widget.configure(state=state)
            except Exception:
                pass
        self._on_setting_change()

    def _on_setting_change(self) -> None:
        """Fire immediately when a pattern/style/char toggle changes."""
        self._scrub()

    def _schedule_scrub(self) -> None:
        """Debounce: wait 300 ms after last keystroke before scrubbing."""
        if self._scrub_job:
            self.after_cancel(self._scrub_job)
        self._scrub_job = self.after(300, self._scrub)

    def _set_group(self, patterns: list[tuple[str, str]], enabled: bool) -> None:
        for name, _ in patterns:
            if name in self._pattern_vars:
                self._pattern_vars[name].set(enabled)
        self._scrub()

    # ── Actions ────────────────────────────────────────────────────────────────

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
            content = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("datascrub", f"Cannot read file:\n{exc}")
            return
        suffix = Path(path).suffix.lower()
        self._file_format = {".json": "json", ".csv": "csv"}.get(suffix, "text")
        self._current_file = Path(path).name
        self._set_input(content)
        self.title(f"datascrub — {self._current_file}")
        self._update_status_format()
        self._scrub()

    def _scrub(self) -> None:
        self._scrub_job = None
        text = self._input_box.get("1.0", "end-1c")
        disabled = frozenset(
            name for name, var in self._pattern_vars.items() if not var.get()
        )
        mask_char = self._resolve_mask_char()
        mask_style = self._mask_style_var.get()
        kwargs = dict(
            categories=None,
            extra_patterns=self._extra_patterns,
            mask_char=mask_char,
            mask_style=mask_style,
            disabled_patterns=disabled,
        )

        if self._file_format == "json":
            result = scrub_json(text, **kwargs)
        elif self._file_format == "csv":
            result = scrub_csv(text, **kwargs)
        else:
            result = scrub(text, **kwargs)

        self._last_result = result

        self._output_box.configure(state="normal")
        self._output_box.delete("1.0", "end")
        self._output_box.insert("1.0", result.text)
        self._output_box.configure(state="disabled")

        self._tree.delete(*self._tree.get_children())
        for idx, f in enumerate(result.findings):
            orig = f.original if len(f.original) <= 46 else f.original[:43] + "…"
            tag = "odd" if idx % 2 else "even"
            self._tree.insert("", "end", values=(
                f.pattern_name, f.category, orig, f.masked,
            ), tags=(tag,))

        count = result.finding_count
        self._findings_label.configure(
            text=f"FINDINGS  —  {count} detected" if count else "FINDINGS  —  none"
        )
        self._output_label.configure(
            text=f"OUTPUT  (masked — {count} replacement{'s' if count != 1 else ''})"
            if count else "OUTPUT  (no sensitive data found)"
        )
        self._status_findings.configure(
            text=f"{count} finding{'s' if count != 1 else ''}"
        )

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
            filetypes=[
                ("Text files", "*.txt"),
                ("JSON files", "*.json"),
                ("CSV files",  "*.csv"),
                ("All files",  "*.*"),
            ],
        )
        if not path:
            return
        try:
            Path(path).write_text(self._last_result.text, encoding="utf-8")
            self._show_toast(f"Saved  {Path(path).name}")
        except OSError as exc:
            messagebox.showerror("datascrub", f"Cannot save file:\n{exc}")

    def _clear(self) -> None:
        self._input_box.delete("1.0", "end")
        self._output_box.configure(state="normal")
        self._output_box.delete("1.0", "end")
        self._output_box.configure(state="disabled")
        self._tree.delete(*self._tree.get_children())
        self._last_result = None
        self._file_format = "text"
        self._current_file = ""
        self.title("datascrub")
        self._findings_label.configure(text="FINDINGS  —  none")
        self._output_label.configure(text="OUTPUT  (masked)")
        self._input_char_label.configure(text="")
        self._status_chars.configure(text="0 chars")
        self._status_findings.configure(text="0 findings")
        self._update_status_format()

    # ── Helpers ────────────────────────────────────────────────────────────────

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
            self._file_format, "Format: text"
        )
        if self._current_file:
            label += f"  ·  {self._current_file}"
        self._status_format.configure(text=label)

    def _show_toast(self, message: str) -> None:
        original = self.title()
        self.title(f"datascrub — {message}")
        self.after(2500, lambda: self.title(original))

    def __init__(self, extra_patterns: Sequence[Pattern] = ()) -> None:
        super().__init__()
        self._extra_patterns = list(extra_patterns)
        self._last_result: ScrubResult | None = None
        self._file_format: str = "text"
        self._current_file: str = ""

        self.title("datascrub")
        self.geometry("1160x760")
        self.minsize(860, 580)

        self._build_layout()
        self._bind_keys()

    # ── Layout ─────────────────────────────────────────────────────────────────

    def _build_layout(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=3)
        self.grid_rowconfigure(1, weight=2)
        self.grid_rowconfigure(2, weight=0)  # status bar

        self._build_sidebar()
        self._build_editor()
        self._build_findings()
        self._build_statusbar()

    def _build_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(self, width=230, corner_radius=0)
        sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(20, weight=1)

        # Title
        ctk.CTkLabel(
            sidebar, text="datascrub",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).grid(row=0, column=0, columnspan=2, padx=16, pady=(18, 6))

        # ── CATEGORIES header + Select All / None ──────────────────────────
        cat_header = ctk.CTkFrame(sidebar, fg_color="transparent")
        cat_header.grid(row=1, column=0, columnspan=2, sticky="ew", padx=12, pady=(10, 2))
        cat_header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            cat_header, text="CATEGORIES",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="gray60",
        ).grid(row=0, column=0, sticky="w")

        toggle_frame = ctk.CTkFrame(cat_header, fg_color="transparent")
        toggle_frame.grid(row=0, column=1, sticky="e")
        ctk.CTkButton(
            toggle_frame, text="All", width=32, height=20,
            font=ctk.CTkFont(size=10),
            fg_color="gray35", hover_color="gray28",
            command=self._select_all_categories,
        ).pack(side="left", padx=(0, 2))
        ctk.CTkButton(
            toggle_frame, text="None", width=38, height=20,
            font=ctk.CTkFont(size=10),
            fg_color="gray35", hover_color="gray28",
            command=self._select_no_categories,
        ).pack(side="left")

        self._cat_vars: dict[str, ctk.BooleanVar] = {}
        for i, cat in enumerate(_ALL_CATEGORIES):
            var = ctk.BooleanVar(value=True)
            self._cat_vars[cat] = var
            ctk.CTkCheckBox(
                sidebar, text=_CATEGORY_LABELS[cat],
                variable=var,
                font=ctk.CTkFont(size=12),
                checkbox_width=18, checkbox_height=18,
            ).grid(row=2 + i, column=0, columnspan=2, padx=16, pady=3, sticky="w")

        # ── MASK CHARACTER ─────────────────────────────────────────────────
        ctk.CTkLabel(
            sidebar, text="MASK CHARACTER",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="gray60",
        ).grid(row=7, column=0, columnspan=2, padx=16, pady=(18, 4), sticky="w")

        self._mask_char_var = tk.StringVar(value="*")

        preset_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        preset_frame.grid(row=8, column=0, columnspan=2, padx=16, sticky="w")
        for label, value in _MASK_PRESETS:
            ctk.CTkRadioButton(
                preset_frame, text=label, value=value,
                variable=self._mask_char_var,
                font=ctk.CTkFont(size=13),
                radiobutton_width=16, radiobutton_height=16,
                command=self._on_mask_char_change,
            ).pack(side="left", padx=(0, 10))

        custom_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        custom_frame.grid(row=9, column=0, columnspan=2, padx=16, pady=(4, 0), sticky="w")
        ctk.CTkRadioButton(
            custom_frame, text="custom:", value="__custom__",
            variable=self._mask_char_var,
            font=ctk.CTkFont(size=12),
            radiobutton_width=16, radiobutton_height=16,
            command=self._on_mask_char_change,
        ).pack(side="left")
        self._custom_mask_entry = ctk.CTkEntry(
            custom_frame, width=50, height=26,
            font=ctk.CTkFont(size=13),
            placeholder_text="?",
        )
        self._custom_mask_entry.pack(side="left", padx=(6, 0))
        self._custom_mask_entry.bind("<KeyRelease>", lambda _: self._on_mask_char_change())

        # ── ACTIONS ────────────────────────────────────────────────────────
        ctk.CTkLabel(
            sidebar, text="ACTIONS",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="gray60",
        ).grid(row=11, column=0, columnspan=2, padx=16, pady=(20, 2), sticky="w")

        btn_cfg = dict(width=198, height=34, font=ctk.CTkFont(size=13))
        ctk.CTkButton(
            sidebar, text="Open file…  (Ctrl+O)", command=self._open_file,
            **btn_cfg,
        ).grid(row=12, column=0, columnspan=2, padx=16, pady=3)
        ctk.CTkButton(
            sidebar, text="Scrub  (Ctrl+R)", command=self._scrub,
            fg_color="#1f6aa5", hover_color="#1a5a8f",
            **btn_cfg,
        ).grid(row=13, column=0, columnspan=2, padx=16, pady=3)
        ctk.CTkButton(
            sidebar, text="Copy output  (Ctrl+C)", command=self._copy,
            fg_color="gray30", hover_color="gray25",
            **btn_cfg,
        ).grid(row=14, column=0, columnspan=2, padx=16, pady=3)
        ctk.CTkButton(
            sidebar, text="Save output…  (Ctrl+S)", command=self._save,
            fg_color="gray30", hover_color="gray25",
            **btn_cfg,
        ).grid(row=15, column=0, columnspan=2, padx=16, pady=3)
        ctk.CTkButton(
            sidebar, text="Clear", command=self._clear,
            fg_color="gray22", hover_color="gray18",
            text_color="gray60",
            **btn_cfg,
        ).grid(row=16, column=0, columnspan=2, padx=16, pady=(3, 8))

    def _build_editor(self) -> None:
        editor = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        editor.grid(row=0, column=1, sticky="nsew", padx=(8, 8), pady=(8, 4))
        editor.grid_columnconfigure(0, weight=1)
        editor.grid_rowconfigure(1, weight=1)
        editor.grid_rowconfigure(3, weight=1)

        # ── Input ──────────────────────────────────────────────────────────
        input_hdr = ctk.CTkFrame(editor, fg_color="transparent")
        input_hdr.grid(row=0, column=0, sticky="ew", padx=4, pady=(0, 2))
        input_hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            input_hdr, text="INPUT",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="gray60",
        ).grid(row=0, column=0, sticky="w")

        self._input_char_label = ctk.CTkLabel(
            input_hdr, text="",
            font=ctk.CTkFont(size=11),
            text_color="gray50",
        )
        self._input_char_label.grid(row=0, column=1, sticky="e")

        self._input_box = ctk.CTkTextbox(
            editor,
            font=ctk.CTkFont(family="monospace", size=12),
            wrap="none",
            border_width=1,
        )
        self._input_box.grid(row=1, column=0, sticky="nsew")
        self._input_box.bind("<KeyRelease>", self._on_input_change)
        self._input_box.bind("<<Paste>>", lambda _: self.after(10, self._on_input_change))

        # ── Output ─────────────────────────────────────────────────────────
        self._output_label = ctk.CTkLabel(
            editor, text="OUTPUT  (masked)",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="gray60",
        )
        self._output_label.grid(row=2, column=0, sticky="w", padx=4, pady=(8, 2))

        self._output_box = ctk.CTkTextbox(
            editor,
            font=ctk.CTkFont(family="monospace", size=12),
            wrap="none",
            border_width=1,
            state="disabled",
            text_color="gray70",
        )
        self._output_box.grid(row=3, column=0, sticky="nsew")

    def _build_findings(self) -> None:
        frame = ctk.CTkFrame(self, corner_radius=0)
        frame.grid(row=1, column=1, sticky="nsew", padx=8, pady=(4, 4))
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        self._findings_label = ctk.CTkLabel(
            frame, text="FINDINGS  —  none",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="gray60",
        )
        self._findings_label.grid(row=0, column=0, sticky="w", padx=10, pady=(6, 2))

        # ttk.Treeview — no CTk equivalent, styled to match dark theme
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Findings.Treeview",
            background="#2b2b2b",
            foreground="white",
            rowheight=22,
            fieldbackground="#2b2b2b",
            borderwidth=0,
            font=("monospace", 11),
        )
        style.configure(
            "Findings.Treeview.Heading",
            background="#1e1e1e",
            foreground="#888888",
            relief="flat",
            font=("monospace", 11, "bold"),
        )
        style.map(
            "Findings.Treeview",
            background=[("selected", "#1f6aa5")],
            foreground=[("selected", "white")],
        )

        cols = ("pattern", "category", "original", "masked")
        self._tree = ttk.Treeview(
            frame, columns=cols, show="headings",
            style="Findings.Treeview", height=6,
        )
        for col, heading, width in [
            ("pattern",  "Pattern",  160),
            ("category", "Category", 110),
            ("original", "Original", 280),
            ("masked",   "Masked",   280),
        ]:
            self._tree.heading(col, text=heading)
            self._tree.column(col, width=width, anchor="w")

        self._tree.tag_configure("odd",  background="#252525")
        self._tree.tag_configure("even", background="#2b2b2b")

        self._tree.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))

        sb = ttk.Scrollbar(frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        sb.grid(row=1, column=1, sticky="ns")
        frame.grid_columnconfigure(1, weight=0)

    # ── Status bar ─────────────────────────────────────────────────────────────

    def _build_statusbar(self) -> None:
        bar = ctk.CTkFrame(self, height=28, corner_radius=0, fg_color="#1a1a1a")
        bar.grid(row=2, column=0, columnspan=2, sticky="ew", padx=0, pady=0)
        bar.grid_columnconfigure(4, weight=1)  # spacer pushes version to right
        bar.grid_propagate(False)

        lbl_cfg = dict(font=ctk.CTkFont(size=11), text_color="gray55", height=28)
        sep_cfg = dict(font=ctk.CTkFont(size=11), text_color="gray35", height=28)

        self._status_format = ctk.CTkLabel(bar, text="Format: text", **lbl_cfg)
        self._status_format.grid(row=0, column=0, padx=(12, 0), sticky="w")

        ctk.CTkLabel(bar, text="│", **sep_cfg).grid(row=0, column=1, padx=8)

        self._status_chars = ctk.CTkLabel(bar, text="0 chars", **lbl_cfg)
        self._status_chars.grid(row=0, column=2, sticky="w")

        ctk.CTkLabel(bar, text="│", **sep_cfg).grid(row=0, column=3, padx=8)

        self._status_findings = ctk.CTkLabel(bar, text="0 findings", **lbl_cfg)
        self._status_findings.grid(row=0, column=4, sticky="w")

        # column 4 has weight=1, so this spacer expands and pushes version right
        ctk.CTkLabel(bar, text=f"v{_VERSION}", **lbl_cfg).grid(
            row=0, column=5, padx=(0, 12), sticky="e"
        )

    # ── Key bindings ───────────────────────────────────────────────────────────

    def _bind_keys(self) -> None:
        self.bind("<Control-r>", lambda _: self._scrub())
        self.bind("<Control-o>", lambda _: self._open_file())
        self.bind("<Control-s>", lambda _: self._save())

    # ── Event handlers ─────────────────────────────────────────────────────────

    def _on_input_change(self, _event=None) -> None:
        n = len(self._input_box.get("1.0", "end-1c"))
        self._input_char_label.configure(text=f"{n:,} chars")
        self._status_chars.configure(text=f"{n:,} chars")

    def _on_mask_char_change(self) -> None:
        if self._last_result is not None:
            self._scrub()

    def _select_all_categories(self) -> None:
        for var in self._cat_vars.values():
            var.set(True)

    def _select_no_categories(self) -> None:
        for var in self._cat_vars.values():
            var.set(False)

    # ── Actions ────────────────────────────────────────────────────────────────

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
            content = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("datascrub", f"Cannot read file:\n{exc}")
            return
        suffix = Path(path).suffix.lower()
        self._file_format = {".json": "json", ".csv": "csv"}.get(suffix, "text")
        self._current_file = Path(path).name
        self._set_input(content)
        self.title(f"datascrub — {self._current_file}")
        self._update_status_format()
        self._scrub()

    def _scrub(self) -> None:
        text = self._input_box.get("1.0", "end-1c")
        cats = {cat for cat, var in self._cat_vars.items() if var.get()}
        mask_char = self._resolve_mask_char()
        kwargs = dict(categories=cats, extra_patterns=self._extra_patterns, mask_char=mask_char)

        if self._file_format == "json":
            result = scrub_json(text, **kwargs)
        elif self._file_format == "csv":
            result = scrub_csv(text, **kwargs)
        else:
            result = scrub(text, **kwargs)

        self._last_result = result

        # Write output
        self._output_box.configure(state="normal")
        self._output_box.delete("1.0", "end")
        self._output_box.insert("1.0", result.text)
        self._output_box.configure(state="disabled")

        # Update findings table with zebra striping
        self._tree.delete(*self._tree.get_children())
        for idx, f in enumerate(result.findings):
            orig = f.original if len(f.original) <= 46 else f.original[:43] + "…"
            tag = "odd" if idx % 2 else "even"
            self._tree.insert("", "end", values=(
                f.pattern_name, f.category, orig, f.masked,
            ), tags=(tag,))

        count = result.finding_count
        self._findings_label.configure(
            text=f"FINDINGS  —  {count} detected" if count else "FINDINGS  —  none"
        )
        self._output_label.configure(
            text=f"OUTPUT  (masked — {count} replacement{'s' if count != 1 else ''})"
            if count else "OUTPUT  (no sensitive data found)"
        )
        self._status_findings.configure(
            text=f"{count} finding{'s' if count != 1 else ''}"
        )

    def _copy(self) -> None:
        if self._last_result is None:
            messagebox.showinfo("datascrub", "Run Scrub first.")
            return
        self.clipboard_clear()
        self.clipboard_append(self._last_result.text)
        self._show_toast("Copied to clipboard")

    def _save(self) -> None:
        if self._last_result is None:
            messagebox.showinfo("datascrub", "Run Scrub first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save masked output",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("JSON files", "*.json"),
                ("CSV files",  "*.csv"),
                ("All files",  "*.*"),
            ],
        )
        if not path:
            return
        try:
            Path(path).write_text(self._last_result.text, encoding="utf-8")
            self._show_toast(f"Saved  {Path(path).name}")
        except OSError as exc:
            messagebox.showerror("datascrub", f"Cannot save file:\n{exc}")

    def _clear(self) -> None:
        self._input_box.delete("1.0", "end")
        self._output_box.configure(state="normal")
        self._output_box.delete("1.0", "end")
        self._output_box.configure(state="disabled")
        self._tree.delete(*self._tree.get_children())
        self._last_result = None
        self._file_format = "text"
        self._current_file = ""
        self.title("datascrub")
        self._findings_label.configure(text="FINDINGS  —  none")
        self._output_label.configure(text="OUTPUT  (masked)")
        self._input_char_label.configure(text="")
        self._status_chars.configure(text="0 chars")
        self._status_findings.configure(text="0 findings")
        self._update_status_format()

    # ── Helpers ────────────────────────────────────────────────────────────────

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
            self._file_format, "Format: text"
        )
        if self._current_file:
            label += f"  ·  {self._current_file}"
        self._status_format.configure(text=label)

    def _show_toast(self, message: str) -> None:
        original = self.title()
        self.title(f"datascrub — {message}")
        self.after(2500, lambda: self.title(original))
