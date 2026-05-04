"""
Pattern definitions for datascrub.

Each Pattern wraps a compiled regex and a masking callable.  Patterns are
grouped by category so the engine and TUI can enable/disable them per group.

Category keys:  "pii" | "credentials" | "financial" | "network" | "custom"
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable


# ── Base class ─────────────────────────────────────────────────────────────────


@dataclass
class Pattern:
    """A single detection + masking rule."""

    name: str
    category: str
    regex: re.Pattern[str]
    masker: Callable[[re.Match[str]], str]
    confidence: float = 1.0  # 0.0–1.0; lower = more false positives expected

    def mask(self, match: re.Match[str]) -> str:
        return self.masker(match)


# ── Shared helpers ─────────────────────────────────────────────────────────────


def _mask_middle(
    value: str,
    keep_start: int = 1,
    keep_end: int = 0,
    char: str = "*",
    min_mask: int = 3,
) -> str:
    """Replace the middle of *value* with mask chars, preserving start/end."""
    mask_len = max(min_mask, len(value) - keep_start - keep_end)
    start = value[:keep_start]
    end = value[len(value) - keep_end :] if keep_end else ""
    return f"{start}{char * mask_len}{end}"


# ── Luhn validation ────────────────────────────────────────────────────────────


def _luhn_valid(digits: str) -> bool:
    """Return True if *digits* satisfies the Luhn checksum."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# ── PII maskers ────────────────────────────────────────────────────────────────


def _mask_email(m: re.Match[str]) -> str:
    local, domain = m.group(0).split("@", 1)
    return f"{local[0]}***@{domain}"


def _mask_ssn(m: re.Match[str]) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    return f"***-**-{digits[-4:]}"


def _mask_phone(m: re.Match[str]) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    return f"***-***-{digits[-4:]}"


# ── Credential maskers ─────────────────────────────────────────────────────────


def _mask_api_key(m: re.Match[str]) -> str:
    """Mask API keys while preserving a short vendor prefix (sk-, ghp_, …)."""
    value = m.group(0)
    prefix_m = re.match(r"^([A-Za-z]{2,4}[-_])", value)
    if prefix_m:
        prefix = prefix_m.group(1)
        rest = value[len(prefix) :]
        tail = rest[-4:] if len(rest) > 8 else ""
        return f"{prefix}****...{tail}" if tail else f"{prefix}****"
    return f"{value[:4]}****...{value[-4:]}"


def _mask_jwt(m: re.Match[str]) -> str:
    parts = m.group(0).split(".", 2)
    # Fix 10: guard against unexpected split results (should always be 3 parts
    # given the regex, but be defensive).
    if len(parts) < 3:
        return m.group(0)
    header, _payload, sig = parts
    return f"{header[:10]}*****.{sig[-8:]}"


def _mask_bearer(m: re.Match[str]) -> str:
    # Fix 11: groups 1 and 2 are guaranteed by the regex pattern — (Bearer\s+)
    # and ([a-zA-Z0-9\-._~+/]+=*).  If the regex is ever changed, update here.
    bearer, token = m.group(1), m.group(2)
    masked = _mask_middle(token, keep_start=4, keep_end=4, char="*", min_mask=4)
    return f"{bearer}{masked}"


def _mask_generic_credential(m: re.Match[str]) -> str:
    """Mask the value portion of key=value credential assignments."""
    offset = m.start(1) - m.start(0)
    masked = _mask_middle(m.group(1), keep_start=4, keep_end=4, char="*", min_mask=4)
    return m.group(0)[:offset] + masked


# ── Financial maskers ──────────────────────────────────────────────────────────


def _mask_credit_card(m: re.Match[str]) -> str:
    raw = m.group(0)
    digits = re.sub(r"[\s\-]", "", raw)
    if len(digits) not in (13, 14, 15, 16) or not _luhn_valid(digits):
        return raw  # spurious match — leave untouched
    sep = "-" if "-" in raw else (" " if " " in raw else "")
    first4, last4 = digits[:4], digits[-4:]
    # Fix 7: Amex uses a 4-6-5 grouping for 15-digit cards (34xx / 37xx);
    # the last 5-digit group is masked as '*{last4}' (mask only the leading
    # digit of the group, preserving the last 4 for identification).
    # All other supported networks use 4-4-4-4 groups.
    if len(digits) == 15:
        if sep:
            return f"{first4}{sep}{'*' * 6}{sep}*{last4}"
        return f"{first4}{'*' * 7}{last4}"
    if sep:
        return f"{first4}{sep}****{sep}****{sep}{last4}"
    return f"{first4}{'*' * (len(digits) - 8)}{last4}"


# ── Network maskers ────────────────────────────────────────────────────────────


def _mask_ipv4(m: re.Match[str]) -> str:
    parts = m.group(0).split(".")
    return f"{parts[0]}.{parts[1]}.*.*"


def _mask_url_credentials(m: re.Match[str]) -> str:
    # https://user:pass@host  →  https://user:****@host
    return f"{m.group(1)}{m.group(2)}:****@"


# ── Pattern registry ───────────────────────────────────────────────────────────

_PATTERNS_PII: list[Pattern] = [
    Pattern(
        name="email",
        category="pii",
        regex=re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
        masker=_mask_email,
    ),
    Pattern(
        name="ssn",
        category="pii",
        regex=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        masker=_mask_ssn,
    ),
    Pattern(
        name="phone",
        category="pii",
        regex=re.compile(
            r"(?<!\d)(?:\+?1[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-])\d{3}[\s.\-]\d{4}(?!\d)"
        ),
        masker=_mask_phone,
    ),
]

_PATTERNS_CREDENTIALS: list[Pattern] = [
    # JWT must be checked before bearer_token to avoid partial overlap
    Pattern(
        name="jwt",
        category="credentials",
        regex=re.compile(
            r"\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b"
        ),
        masker=_mask_jwt,
    ),
    Pattern(
        name="bearer_token",
        category="credentials",
        regex=re.compile(r"(?i)(Bearer\s+)([a-zA-Z0-9\-._~+/]+=*)"),
        masker=_mask_bearer,
    ),
    Pattern(
        name="openai_key",
        category="credentials",
        regex=re.compile(r"\bsk-[a-zA-Z0-9]{32,}\b"),
        masker=_mask_api_key,
    ),
    Pattern(
        name="github_token",
        category="credentials",
        # gh[pousr]_ covers personal (ghp), oauth (gho), user-to-server (ghu),
        # server-to-server (ghs), refresh (ghr) token prefixes
        regex=re.compile(r"\bgh[poushr]_[a-zA-Z0-9]{36}\b"),
        masker=_mask_api_key,
    ),
    Pattern(
        name="aws_access_key",
        category="credentials",
        regex=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        masker=_mask_api_key,
    ),
    Pattern(
        name="generic_credential",
        category="credentials",
        regex=re.compile(
            r"(?i)(?:api[_\-]?key|api[_\-]?secret|access[_\-]?token"
            r"|auth[_\-]?token|secret[_\-]?key)"
            r"""(?:["\s:=']+)([a-zA-Z0-9\-_.+/]{20,})"""
        ),
        masker=_mask_generic_credential,
        confidence=0.8,
    ),
]

_PATTERNS_FINANCIAL: list[Pattern] = [
    Pattern(
        name="credit_card",
        category="financial",
        regex=re.compile(
            # Fix 7: two alternations — Amex 4-6-5 (15 digits) first, then the
            # standard 4-4-4-4 (16-digit) format for Visa, MC, and Discover.
            # Amex BIN prefixes: 34xx, 37xx
            r"\b(?:"
            r"3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}"
            r"|"
            r"(?:4[0-9]{3}|5[1-5][0-9]{2}|6(?:011|5[0-9]{2}))(?:[-\s]?[0-9]{4}){3}"
            r")\b"
        ),
        masker=_mask_credit_card,
    ),
]

_PATTERNS_NETWORK: list[Pattern] = [
    # URL credentials before plain IPv4 so embedded IPs aren't double-processed.
    # Matches any URI scheme (https, postgres, mongodb, redis, …).
    Pattern(
        name="url_credentials",
        category="network",
        regex=re.compile(r"([a-zA-Z][a-zA-Z0-9+\-.]*://)([^:@/\s]+):([^@/\s]+)@"),
        masker=_mask_url_credentials,
    ),
    Pattern(
        name="ipv4",
        category="network",
        regex=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        masker=_mask_ipv4,
        confidence=0.7,
    ),
]

CATEGORIES: dict[str, list[Pattern]] = {
    "pii": _PATTERNS_PII,
    "credentials": _PATTERNS_CREDENTIALS,
    "financial": _PATTERNS_FINANCIAL,
    "network": _PATTERNS_NETWORK,
}

# Deterministic application order — credentials before pii before financial
# before network reduces interaction between overlapping regexes.
_CATEGORY_ORDER = ("credentials", "pii", "financial", "network")


def get_patterns(categories: set[str] | None = None) -> list[Pattern]:
    """Return compiled patterns for the requested categories (all if *None*)."""
    active = set(CATEGORIES) if categories is None else categories
    return [p for cat in _CATEGORY_ORDER if cat in active for p in CATEGORIES[cat]]
