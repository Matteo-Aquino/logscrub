r"""
YAML config loading and CLI flag merging for datascrub.

Config file schema (all keys optional)
---------------------------------------
categories:
  pii: true
  credentials: true
  financial: true
  network: true

custom_patterns:
  - name: my_internal_id
    category: custom
    # Use single-quoted YAML strings for patterns — backslashes are literal,
    # so \b, \d, \w etc. reach re.compile() unchanged.
    pattern: '\bINT-[0-9]{6}\b'
    mask: "INT-******"        # literal replacement string
    # OR use partial masking:
    # keep_start: 4
    # keep_end: 2
    # char: "*"

Example usage
-------------
  datascrub -c ~/.datascrub.yml -i data.txt
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .patterns import Pattern, _mask_middle

try:
    import yaml  # PyYAML
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


# ── Config dataclass ───────────────────────────────────────────────────────────


@dataclass
class Config:
    """Resolved configuration: category toggles + custom patterns."""

    categories: dict[str, bool] = field(default_factory=lambda: {
        "pii": True,
        "credentials": True,
        "financial": True,
        "network": True,
    })
    custom_patterns: list[dict[str, Any]] = field(default_factory=list)

    def active_categories(self) -> set[str]:
        enabled = {cat for cat, on in self.categories.items() if on}
        if any(p.get("category", "custom") == "custom" for p in self.custom_patterns):
            enabled.add("custom")
        return enabled


# ── Loader ─────────────────────────────────────────────────────────────────────


def load_config(path: str | Path) -> Config:
    """Parse a YAML config file and return a :class:`Config`.

    Raises ``ImportError`` if PyYAML is not installed.
    Raises ``ValueError`` for malformed config content.
    Raises ``OSError`` if the file cannot be read.
    """
    if not _YAML_AVAILABLE:
        raise ImportError(
            "PyYAML is required for config file support.\n"
            "Install with: pip install pyyaml"
        )

    raw = Path(path).read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in config file: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Config file must be a YAML mapping at the top level.")

    cfg = Config()

    # Category toggles
    if "categories" in data:
        cats = data["categories"]
        if not isinstance(cats, dict):
            raise ValueError("'categories' must be a mapping.")
        for key, val in cats.items():
            if key in cfg.categories:
                cfg.categories[key] = bool(val)

    # Custom patterns (validated but not compiled here)
    if "custom_patterns" in data:
        raw_patterns = data["custom_patterns"]
        if not isinstance(raw_patterns, list):
            raise ValueError("'custom_patterns' must be a list.")
        for i, entry in enumerate(raw_patterns):
            _validate_custom_pattern(entry, index=i)
        cfg.custom_patterns = raw_patterns

    return cfg


def _validate_custom_pattern(entry: Any, index: int) -> None:
    if not isinstance(entry, dict):
        raise ValueError(f"custom_patterns[{index}] must be a mapping.")
    if "name" not in entry:
        raise ValueError(f"custom_patterns[{index}] missing required key 'name'.")
    if "pattern" not in entry:
        raise ValueError(f"custom_patterns[{index}] missing required key 'pattern'.")
    try:
        re.compile(entry["pattern"])
    except re.error as exc:
        raise ValueError(
            f"custom_patterns[{index}] ({entry.get('name')!r}) "
            f"has invalid regex: {exc}"
        ) from exc


# ── Pattern builder ────────────────────────────────────────────────────────────


def build_extra_patterns(cfg: Config) -> list[Pattern]:
    """Compile the custom_patterns from a :class:`Config` into Pattern objects."""
    patterns: list[Pattern] = []
    for entry in cfg.custom_patterns:
        patterns.append(_compile_custom(entry))
    return patterns


def _compile_custom(entry: dict[str, Any]) -> Pattern:
    name = entry["name"]
    category = entry.get("category", "custom")
    regex = re.compile(entry["pattern"])

    # Masking strategy: literal string > partial > full-star replacement
    if "mask" in entry:
        literal = str(entry["mask"])
        masker = lambda m, _lit=literal: _lit  # noqa: E731
    elif "keep_start" in entry or "keep_end" in entry:
        keep_start = int(entry.get("keep_start", 0))
        keep_end = int(entry.get("keep_end", 0))
        char = str(entry.get("char", "*"))
        masker = lambda m, ks=keep_start, ke=keep_end, c=char: _mask_middle(  # noqa: E731
            m.group(0), keep_start=ks, keep_end=ke, char=c
        )
    else:
        # Default: replace entire match with stars of the same length
        char = str(entry.get("char", "*"))
        masker = lambda m, c=char: c * len(m.group(0))  # noqa: E731

    return Pattern(name=name, category=category, regex=regex, masker=masker)


