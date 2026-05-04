"""
Policy profiles for datascrub.

A profile is a named snapshot of all scrub settings: which patterns are
enabled, which masking style to use, the mask character, and the allowlist.
Profiles are stored as JSON files in a platform-appropriate config directory.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

import platformdirs


_APP_NAME = "datascrub"
_PROFILES_DIR = Path(platformdirs.user_config_dir(_APP_NAME)) / "profiles"

# Built-in preset profiles
_BUILTIN_PROFILES: list[dict] = [
    {
        "name": "GDPR",
        "mask_style": "redacted",
        "mask_char": "*",
        "disabled_patterns": [],
        "allowlist": [],
        "description": "GDPR — redact all PII and credentials",
    },
    {
        "name": "HIPAA",
        "mask_style": "token",
        "mask_char": "*",
        "disabled_patterns": ["ipv4", "url_credentials"],
        "allowlist": [],
        "description": "HIPAA — tokenise PHI for consistent de-identification",
    },
    {
        "name": "SOC2",
        "mask_style": "partial",
        "mask_char": "*",
        "disabled_patterns": ["ipv4"],
        "allowlist": [],
        "description": "SOC2 — partial masking of credentials and PII",
    },
    {
        "name": "Minimal",
        "mask_style": "partial",
        "mask_char": "*",
        "disabled_patterns": ["ipv4", "generic_credential", "url_credentials", "phone"],
        "allowlist": [],
        "description": "Low-noise — only high-confidence patterns",
    },
]


@dataclass
class Profile:
    name: str
    mask_style: str = "partial"
    mask_char: str = "*"
    disabled_patterns: list[str] = field(default_factory=list)
    allowlist: list[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Profile":
        return cls(
            name=d.get("name", "Unnamed"),
            mask_style=d.get("mask_style", "partial"),
            mask_char=d.get("mask_char", "*"),
            disabled_patterns=list(d.get("disabled_patterns", [])),
            allowlist=list(d.get("allowlist", [])),
            description=d.get("description", ""),
        )


def _ensure_dir() -> None:
    _PROFILES_DIR.mkdir(parents=True, exist_ok=True)


def list_profiles() -> list[Profile]:
    """Return profiles: built-ins first, then user-saved (user saves shadow builtins by name)."""
    builtin = {p["name"]: Profile.from_dict(p) for p in _BUILTIN_PROFILES}
    _ensure_dir()
    user: dict[str, Profile] = {}
    for path in sorted(_PROFILES_DIR.glob("*.json")):
        try:
            p = Profile.from_dict(json.loads(path.read_text(encoding="utf-8")))
            user[p.name] = p
        except Exception:
            pass
    # Merge: user profiles override built-ins with the same name
    merged = {**builtin, **user}
    return list(merged.values())


def save_profile(profile: Profile) -> Path:
    """Persist a profile to disk.  Returns the path written."""
    _ensure_dir()
    safe_name = "".join(c if c.isalnum() or c in "-_ " else "_" for c in profile.name)
    path = _PROFILES_DIR / f"{safe_name}.json"
    path.write_text(json.dumps(profile.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def delete_profile(name: str) -> bool:
    """Delete a user-saved profile by name.  Returns True if deleted."""
    safe_name = "".join(c if c.isalnum() or c in "-_ " else "_" for c in name)
    path = _PROFILES_DIR / f"{safe_name}.json"
    if path.exists():
        path.unlink()
        return True
    return False


def get_profile(name: str) -> Profile | None:
    """Fetch a profile by name (built-in or saved)."""
    for p in list_profiles():
        if p.name == name:
            return p
    return None
