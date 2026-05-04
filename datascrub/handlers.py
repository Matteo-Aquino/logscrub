"""
Format handlers for datascrub.

Each handler accepts raw text, scrubs it, and returns a ScrubResult.

- scrub_json  — walks the decoded JSON tree, scrubs every string value in
                place, then re-serialises with the original indentation
- scrub_csv   — processes each cell individually so structure is preserved;
                handles quoted fields and embedded newlines via the stdlib
                csv module

Plain text passes directly to :func:`datascrub.engine.scrub`.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Sequence

from .engine import scrub, ScrubResult, Finding
from .patterns import Pattern


# ── JSON ───────────────────────────────────────────────────────────────────────


def scrub_json(
    text: str,
    categories: set[str] | None = None,
    extra_patterns: Sequence[Pattern] = (),
    mask_char: str = "*",
    mask_style: str = "partial",
    disabled_patterns: frozenset[str] = frozenset(),
    allowlist: frozenset[str] = frozenset(),
    token_map: dict[str, str] | None = None,
) -> ScrubResult:
    """Scrub all string values inside a JSON document, preserving structure.

    Falls back to plain-text scrubbing if the input is not valid JSON.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return scrub(text, categories=categories, extra_patterns=extra_patterns,
                     mask_char=mask_char, mask_style=mask_style,
                     disabled_patterns=disabled_patterns, allowlist=allowlist,
                     token_map=token_map)

    indent = _detect_json_indent(text)
    all_findings: list[Finding] = []
    if token_map is None:
        token_map = {}

    def _walk(node: Any) -> Any:
        if isinstance(node, str):
            result = scrub(node, categories=categories, extra_patterns=extra_patterns,
                           mask_char=mask_char, mask_style=mask_style,
                           disabled_patterns=disabled_patterns, allowlist=allowlist,
                           token_map=token_map)
            all_findings.extend(result.findings)
            return result.text
        if isinstance(node, dict):
            return {k: _walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(item) for item in node]
        return node

    scrubbed_data = _walk(data)
    scrubbed_text = json.dumps(scrubbed_data, indent=indent, ensure_ascii=False)
    # Preserve trailing newline if original had one
    if text.endswith("\n") and not scrubbed_text.endswith("\n"):
        scrubbed_text += "\n"

    return ScrubResult(text=scrubbed_text, findings=all_findings)


def _detect_json_indent(text: str) -> int | None:
    """Return the indentation width found in *text*, or None for compact."""
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped and stripped != line:
            return len(line) - len(stripped)
    return None


# ── CSV ────────────────────────────────────────────────────────────────────────


def scrub_csv(
    text: str,
    categories: set[str] | None = None,
    extra_patterns: Sequence[Pattern] = (),
    mask_char: str = "*",
    mask_style: str = "partial",
    disabled_patterns: frozenset[str] = frozenset(),
    allowlist: frozenset[str] = frozenset(),
    token_map: dict[str, str] | None = None,
) -> ScrubResult:
    """Scrub every cell in a CSV document, preserving rows and columns.

    The dialect (delimiter, quoting) is sniffed from the first 4 KB.
    Falls back to plain-text scrubbing on parse errors.
    """
    try:
        sniffer = csv.Sniffer()
        dialect = sniffer.sniff(text[:4096], delimiters=",\t;|")
        has_header = sniffer.has_header(text[:4096])
    except csv.Error:
        return scrub(text, categories=categories, extra_patterns=extra_patterns,
                     mask_char=mask_char, mask_style=mask_style,
                     disabled_patterns=disabled_patterns, allowlist=allowlist,
                     token_map=token_map)

    reader = csv.reader(io.StringIO(text), dialect)

    all_findings: list[Finding] = []
    out_rows: list[list[str]] = []
    if token_map is None:
        token_map = {}

    for row_idx, row in enumerate(reader):
        out_row: list[str] = []
        for cell in row:
            # Leave the header row intact so column names are not masked
            if row_idx == 0 and has_header:
                out_row.append(cell)
                continue
            result = scrub(cell, categories=categories, extra_patterns=extra_patterns,
                           mask_char=mask_char, mask_style=mask_style,
                           disabled_patterns=disabled_patterns, allowlist=allowlist,
                           token_map=token_map)
            all_findings.extend(result.findings)
            out_row.append(result.text)
        out_rows.append(out_row)

    buf = io.StringIO()
    writer = csv.writer(buf, dialect)
    writer.writerows(out_rows)
    scrubbed_text = buf.getvalue()

    return ScrubResult(text=scrubbed_text, findings=all_findings)
