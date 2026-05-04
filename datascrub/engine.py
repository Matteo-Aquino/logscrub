"""
Scrub engine — orchestrates pattern matching and produces masked output + findings.

The engine does a single-pass, non-overlapping scan of the input text.  All
active patterns are tried at every position; the earliest (then longest) match
wins.  This prevents double-masking and gives predictable results regardless of
pattern order.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Sequence

from .patterns import Pattern, get_patterns


# ── Data structures ────────────────────────────────────────────────────────────


@dataclass
class Finding:
    """One detected sensitive value and its masked replacement."""

    pattern_name: str
    category: str
    original: str
    masked: str
    start: int  # byte offset in the *original* text
    end: int
    confidence: float = 1.0  # inherited from the Pattern that produced this


@dataclass
class ScrubResult:
    """Output of a scrub operation."""

    text: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def summary_by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.category] = counts.get(f.category, 0) + 1
        return counts


# ── Core scrub logic ───────────────────────────────────────────────────────────


def scrub(
    text: str,
    categories: set[str] | None = None,
    extra_patterns: Sequence[Pattern] = (),
    mask_char: str = "*",
    mask_style: str = "partial",
    disabled_patterns: frozenset[str] = frozenset(),
    allowlist: frozenset[str] = frozenset(),
    token_map: dict[str, str] | None = None,
) -> ScrubResult:
    """Scan *text*, mask all sensitive values, return a :class:`ScrubResult`.

    Parameters
    ----------
    text:
        Raw input string to sanitise.
    categories:
        Set of category names to enable (``None`` = all built-in categories).
    extra_patterns:
        Additional :class:`~datascrub.patterns.Pattern` instances to apply
        (e.g. loaded from a YAML custom-patterns config).
    mask_char:
        Character used for masking (used by ``partial`` and ``full`` styles).
    mask_style:
        How to render the masked value.  One of:

        - ``"partial"``  — keep first/last chars, fill middle (default)
        - ``"label"``    — replace with ``[PATTERN_NAME]``
        - ``"full"``     — replace entirely with *mask_char* repeated
        - ``"redacted"`` — replace with ``[REDACTED]``
        - ``"token"``    — replace with a consistent ``[TOKEN-N]`` so the same
                           value always maps to the same token within a scrub
                           session; pass a shared *token_map* dict to make
                           tokens consistent across multiple calls.
    disabled_patterns:
        Names of patterns to skip entirely (e.g. ``frozenset({"ssn", "phone"})``).
    allowlist:
        Literal string values to skip even if a pattern would match them.
    token_map:
        Dict mapping original value → token string.  Mutated in-place so the
        same token is reused for repeated occurrences.  Pass the same dict
        across multiple :func:`scrub` calls to maintain consistency.
    """
    patterns = list(get_patterns(categories)) + list(extra_patterns)

    if not patterns or not text:
        return ScrubResult(text=text)

    if token_map is None:
        token_map = {}

    findings: list[Finding] = []
    out_parts: list[str] = []
    pos = 0  # current position in *text*

    candidates = _collect_candidates(text, patterns)

    for start, end, pattern, match in candidates:
        if start < pos:
            continue
        if pattern.name in disabled_patterns:
            continue

        original = text[start:end]
        if original in allowlist:
            continue

        out_parts.append(text[pos:start])

        if mask_style == "label":
            masked = f"[{pattern.name.upper()}]"
        elif mask_style == "full":
            masked = mask_char * len(match.group(0))
        elif mask_style == "redacted":
            masked = "[REDACTED]"
        elif mask_style == "token":
            if original not in token_map:
                token_map[original] = f"[{pattern.category.upper()}-{len(token_map) + 1:03d}]"
            masked = token_map[original]
        else:  # "partial"
            masked = pattern.mask(match)
            if mask_char != "*":
                masked = masked.replace("*", mask_char)

        out_parts.append(masked)

        findings.append(
            Finding(
                pattern_name=pattern.name,
                category=pattern.category,
                original=original,
                masked=masked,
                start=start,
                end=end,
                confidence=pattern.confidence,
            )
        )
        pos = end

    # Append any trailing text after the last match.
    out_parts.append(text[pos:])

    return ScrubResult(text="".join(out_parts), findings=findings)


# ── Internal helpers ───────────────────────────────────────────────────────────


def _collect_candidates(
    text: str,
    patterns: list[Pattern],
) -> list[tuple[int, int, Pattern, re.Match[str]]]:
    """Return all matches for all patterns, sorted earliest-start then longest."""
    candidates: list[tuple[int, int, Pattern, re.Match[str]]] = []

    for pattern in patterns:
        for m in pattern.regex.finditer(text):
            candidates.append((m.start(), m.end(), pattern, m))

    # Primary sort: earliest start; secondary: longest span (greedy wins).
    candidates.sort(key=lambda c: (c[0], -(c[1] - c[0])))
    return candidates
