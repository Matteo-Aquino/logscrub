"""
Policy profiles for datascrub.

A profile is a named snapshot of all scrub settings: which patterns are
enabled, which masking style to use, the mask character, and the allowlist.
Profiles are stored as JSON files in a platform-appropriate config directory.
"""

from __future__ import annotations

import json
import sys
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path

import platformdirs


_APP_NAME = "datascrub"

# Fix 16: compute _PROFILES_DIR lazily so that a platform error at import time
# does not prevent the module from loading.
_PROFILES_DIR: Path | None = None
_PROFILES_DIR_LOCK = threading.Lock()


def _get_profiles_dir() -> Path:
    global _PROFILES_DIR
    with _PROFILES_DIR_LOCK:
        if _PROFILES_DIR is None:
            _PROFILES_DIR = Path(platformdirs.user_config_dir(_APP_NAME)) / "profiles"
        return _PROFILES_DIR


# Fix 13: in-memory cache invalidated by save/delete operations.
# Protected by _CACHE_LOCK for thread-safety.
_profiles_cache: list[Profile] | None = None
_CACHE_LOCK = threading.Lock()


def _invalidate_cache() -> None:
    global _profiles_cache
    with _CACHE_LOCK:
        _profiles_cache = None


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


def _ensure_dir() -> Path:
    # Fix 16: directory resolution is deferred until first use.
    profiles_dir = _get_profiles_dir()
    profiles_dir.mkdir(parents=True, exist_ok=True)
    return profiles_dir


def list_profiles() -> list[Profile]:
    """Return profiles: built-ins first, then user-saved (user saves shadow builtins by name)."""
    global _profiles_cache
    with _CACHE_LOCK:
        if _profiles_cache is not None:
            # Return fresh copies so callers cannot mutate cached state.
            return [Profile.from_dict(p.to_dict()) for p in _profiles_cache]

        builtin = {p["name"]: Profile.from_dict(p) for p in _BUILTIN_PROFILES}
        profiles_dir = _ensure_dir()
        user: dict[str, Profile] = {}
        for path in sorted(profiles_dir.glob("*.json")):
            try:
                p = Profile.from_dict(json.loads(path.read_text(encoding="utf-8")))
                user[p.name] = p
            except Exception as exc:
                # Fix 8: surface corrupt-profile errors so they are not silently lost.
                print(
                    f"datascrub: warning — could not load profile {path.name!r}: {exc}",
                    file=sys.stderr,
                )
        # Merge: user profiles override built-ins with the same name
        merged = {**builtin, **user}
        _profiles_cache = list(merged.values())
        # Return copies so callers cannot mutate cached state.
        return [Profile.from_dict(p.to_dict()) for p in _profiles_cache]


def save_profile(profile: Profile) -> Path:
    """Persist a profile to disk.  Returns the path written.

    Raises ``FileExistsError`` if a *different* profile already occupies the
    same filename slot (two distinct profile names that sanitise to the same
    filename would silently overwrite each other).  To intentionally overwrite
    an existing profile, delete it first with :func:`delete_profile` and then
    call this function again.
    """
    profiles_dir = _ensure_dir()
    safe_name = "".join(c if c.isalnum() or c in "-_ " else "_" for c in profile.name)
    path = profiles_dir / f"{safe_name}.json"

    # Fix 3: detect name-collision — two distinct profile names that map to the
    # same sanitised filename would silently overwrite each other.
    if path.exists():
        try:
            existing = Profile.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except Exception:
            existing = None
        if existing is not None and existing.name != profile.name:
            raise FileExistsError(
                f"Profile name {profile.name!r} maps to the same file as the "
                f"existing profile {existing.name!r} ({path.name}). "
                "Rename one of them to avoid the collision."
            )

    path.write_text(json.dumps(profile.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    _invalidate_cache()
    return path


def delete_profile(name: str) -> bool:
    """Delete a user-saved profile by name.  Returns True if deleted."""
    safe_name = "".join(c if c.isalnum() or c in "-_ " else "_" for c in name)
    profiles_dir = _get_profiles_dir()
    path = profiles_dir / f"{safe_name}.json"
    if path.exists():
        path.unlink()
        _invalidate_cache()
        return True
    return False


def get_profile(name: str) -> Profile | None:
    """Fetch a profile by name (built-in or saved).

    Uses the in-memory cache populated by :func:`list_profiles` to avoid
    repeated disk I/O.
    """
    for p in list_profiles():
        if p.name == name:
            return p
    return None
