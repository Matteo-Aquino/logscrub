#!/usr/bin/env python3
"""
LogScrub  |sanitize  — Splunk streaming search command (UCC add-on).

Usage
-----
    ... | sanitize
    ... | sanitize standard=hipaa fields=_raw,message
    ... | sanitize standard=pci  mask_style=full
    ... | sanitize standard=all  configuration=custom.yaml
    ... | sanitize standard=none configuration=strict.yaml report_findings=false

Parameters
----------
standard        gdpr | hipaa | pci | soc2 | all | none   (default: from Configuration page, fallback gdpr)
configuration   <filename.yaml> | none                   (default: none)
fields          comma-separated field names               (default: _raw)
mask_style      partial | full | label | redacted | token (default: from Configuration page, fallback partial)
min_confidence  0-100                                     (default: from Configuration page, fallback 0)
report_findings true | false                              (default: from Configuration page, fallback true)

Settings priority (highest → lowest)
--------------------------------------
1. SPL command parameter       e.g.  standard=hipaa
2. YAML configuration= file    e.g.  configuration=custom.yaml
3. UCC Configuration page      Splunk Web > Apps > LogScrub > Configuration > Settings
4. Built-in defaults           gdpr / partial / 0 / true
"""
from __future__ import annotations

import logging
import os
import re
import sys

# ── Path setup ─────────────────────────────────────────────────────────────────
# Production: lib/ contains logscrub + splunklib (copied by ucc-gen / sync_lib.sh).
# Development: fall back to the repo root so changes are picked up immediately.
_HERE      = os.path.dirname(os.path.abspath(__file__))
_APP_ROOT  = os.path.dirname(_HERE)           # TA-logscrub/ (installed) OR package/
_LIB       = os.path.join(_APP_ROOT, 'lib')
_REPO_ROOT = os.path.dirname(os.path.dirname(_APP_ROOT))  # project root (dev)

sys.path.insert(0, _LIB)
sys.path.insert(0, _REPO_ROOT)

from splunklib.searchcommands import (          # noqa: E402
    dispatch, StreamingCommand, Configuration, Option, validators,
)
from logscrub.engine import scrub               # noqa: E402
from logscrub.patterns import get_patterns, Pattern  # noqa: E402


# ── Logging ───────────────────────────────────────────────────────────────────

logger = logging.getLogger('logscrub.sanitize')


# ── Built-in compliance standards ─────────────────────────────────────────────

_BUILTIN_STANDARDS: dict[str, set[str] | None] = {
    "gdpr": {
        "email", "phone", "ssn", "us_passport",
        "ipv4", "mac_address",
        "credit_card", "iban",
        "url_credentials", "generic_credential",
    },
    "hipaa": {
        "email", "phone", "ssn", "us_passport",
        "credit_card", "ipv4",
        "url_credentials", "generic_credential",
    },
    "pci": {
        "credit_card", "iban",
        "url_credentials", "generic_credential",
    },
    "soc2": {
        "jwt", "bearer_token",
        "openai_key", "github_token", "aws_access_key",
        "slack_token", "stripe_key", "google_api_key",
        "anthropic_key", "sendgrid_key",
        "url_credentials", "generic_credential",
    },
    "all":  None,   # None  → every pattern active
    "none": set(),  # empty → nothing runs (use with configuration=)
}


# ── Conf file parsers ─────────────────────────────────────────────────────────

def _parse_conf(path: str) -> dict[str, dict[str, str]]:
    """Parse a Splunk .conf file → {stanza: {key: value}}."""
    result: dict[str, dict[str, str]] = {}
    current: str | None = None
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    current = line[1:-1].strip()
                    result.setdefault(current, {})
                elif "=" in line and current is not None:
                    k, _, v = line.partition("=")
                    result[current][k.strip()] = v.strip()
    except OSError:
        pass
    return result


def _read_conf_merged(app_root: str, conf_name: str) -> dict[str, dict[str, str]]:
    """
    Read default/<conf_name>.conf then overlay local/<conf_name>.conf.
    local/ values win (standard Splunk merge behaviour).
    """
    merged: dict[str, dict[str, str]] = {}
    for tier in ("default", "local"):
        path = os.path.join(app_root, tier, conf_name)
        for stanza, kvs in _parse_conf(path).items():
            merged.setdefault(stanza, {}).update(kvs)
    return merged


def _read_ucc_settings(app_root: str) -> dict[str, str]:
    """Return the [settings] stanza from ta_logscrub_settings.conf."""
    conf = _read_conf_merged(app_root, "ta_logscrub_settings.conf")
    return conf.get("settings", {})


def _read_logscrub_conf(app_root: str) -> dict[str, dict[str, str]]:
    """Return the merged logscrub.conf (compliance standard definitions)."""
    return _read_conf_merged(app_root, "logscrub.conf")


def _read_lookup_allowlist(app_root: str) -> frozenset[str]:
    """
    Read logscrub_allowlist.csv from <app_root>/lookups/ and return all values
    in the first column as a frozenset.  Missing file is silently ignored.
    """
    import csv
    path = os.path.join(app_root, "lookups", "logscrub_allowlist.csv")
    if not os.path.exists(path):
        return frozenset()
    values: set[str] = set()
    try:
        with open(path, encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                # Support both "value" header and bare first column
                val = row.get("value") or next(iter(row.values()), None)
                if val and val.strip():
                    values.add(val.strip())
    except OSError:
        pass
    return frozenset(values)


# ── Standard → allowed pattern names ─────────────────────────────────────────

def _resolve_allowed(
    standard: str,
    logscrub_conf: dict[str, dict[str, str]],
) -> set[str] | None:
    """
    Return the set of *allowed* pattern names for *standard*, or None (= all).
    logscrub.conf stanzas override built-in defaults.
    """
    std = standard.lower()
    if std in logscrub_conf:
        raw = logscrub_conf[std].get("patterns", "*").strip()
        if raw == "*":
            return None
        return {p.strip() for p in raw.split(",") if p.strip()}
    return _BUILTIN_STANDARDS.get(std, _BUILTIN_STANDARDS["gdpr"])


# ── YAML configuration loader ─────────────────────────────────────────────────

def _load_yaml_config(cfg_arg: str, app_root: str) -> dict:
    """
    Load a YAML configuration file.
    Bare filenames are resolved relative to <app_root>/lookups/.
    """
    try:
        import yaml
    except ImportError:
        logger.warning("pyyaml not available — configuration= parameter ignored.")
        return {}

    path = cfg_arg if os.path.isabs(cfg_arg) else os.path.join(
        app_root, "lookups", cfg_arg
    )
    if not os.path.exists(path):
        logger.warning("Configuration file not found: %s", path)
        return {}
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


# ── The command ───────────────────────────────────────────────────────────────

@Configuration()
class SanitizeCommand(StreamingCommand):
    """
    Scrub PII and secrets from event fields using the LogScrub pattern library.

    ##Syntax

        | sanitize [standard=<name>] [configuration=<file>]
                   [fields=<field-list>] [mask_style=<style>]
                   [min_confidence=<0-100>] [report_findings=<bool>]

    ##Description

    Masks sensitive values in the specified fields according to the selected
    compliance standard. Findings are reported in <field>_findings and
    <field>_finding_count fields (disable with report_findings=false).

    Global defaults are configured in the add-on's Configuration page in
    Splunk Web. Command parameters always override the global defaults.

    ##Examples

        index=app_logs | sanitize

        index=app_logs | sanitize standard=hipaa fields=_raw,email

        index=app_logs | sanitize standard=pci mask_style=full

        index=app_logs | sanitize standard=soc2 mask_style=label

        index=app_logs | sanitize standard=none configuration=internal.yaml

        index=app_logs | sanitize min_confidence=70 report_findings=false
    """

    standard = Option(
        name="standard",
        require=False,
        default=None,
        doc="Compliance standard: gdpr | hipaa | pci | soc2 | all | none",
    )

    configuration = Option(
        name="configuration",
        require=False,
        default=None,
        doc=(
            "YAML config in lookups/ or absolute path. "
            "Supports: allowlist, disabled_patterns, min_confidence, "
            "mask_style, custom_patterns."
        ),
    )

    fields = Option(
        name="fields",
        require=False,
        default=None,
        doc="Comma-separated fields to scrub.  (default: _raw)",
    )

    mask_style = Option(
        name="mask_style",
        require=False,
        default=None,
        validate=validators.Set("partial", "full", "label", "redacted", "token"),
        doc="partial | full | label | redacted | token",
    )

    min_confidence = Option(
        name="min_confidence",
        require=False,
        default=None,
        validate=validators.Integer(minimum=0, maximum=100),
        doc="Only mask patterns with confidence ≥ this value / 100.",
    )

    report_findings = Option(
        name="report_findings",
        require=False,
        default=None,
        validate=validators.Boolean(),
        doc="Add <field>_findings and <field>_finding_count fields.",
    )

    # ── stream ────────────────────────────────────────────────────────────────

    def stream(self, records):
        # ── 1. Read admin-configured defaults from UCC settings ───────────────
        ucc = _read_ucc_settings(_APP_ROOT)

        # ── 2. Resolve effective parameter values (SPL > UCC > built-in) ──────
        effective_standard       = str(self.standard      or ucc.get("default_standard",        "gdpr"))
        effective_mask_style     = str(self.mask_style    or ucc.get("default_mask_style",       "partial"))
        effective_report         = (
            self.report_findings
            if self.report_findings is not None
            else (ucc.get("default_report_findings", "1").strip() not in ("0", "false", ""))
        )
        effective_min_conf: float = (
            int(self.min_confidence) / 100.0
            if self.min_confidence is not None
            else int(ucc.get("default_min_confidence", "0")) / 100.0
        )
        effective_fields = [
            f.strip()
            for f in str(self.fields or "_raw").split(",")
            if f.strip()
        ]

        # Global allowlist from admin settings (UCC Configuration page)
        ucc_allowlist_raw = ucc.get("default_allowlist", "")
        ucc_allowlist: frozenset[str] = frozenset(
            v.strip() for v in ucc_allowlist_raw.split(",") if v.strip()
        ) if ucc_allowlist_raw else frozenset()

        # Lookup-driven allowlist from logscrub_allowlist.csv (managed via Splunk UI)
        lookup_allowlist: frozenset[str] = _read_lookup_allowlist(_APP_ROOT)

        # ── 3. Resolve which patterns are active for the chosen standard ───────
        logscrub_conf = _read_logscrub_conf(_APP_ROOT)
        allowed = _resolve_allowed(effective_standard, logscrub_conf)
        all_names = {p.name for p in get_patterns()}

        disabled: frozenset[str] = (
            frozenset() if allowed is None else frozenset(all_names - allowed)
        )

        # ── 4. Overlay YAML configuration (if provided) ───────────────────────
        extra_disabled: frozenset[str] = frozenset()
        yaml_allowlist: frozenset[str] = frozenset()
        extra_patterns: list[Pattern]  = []

        cfg_arg = str(self.configuration or "").strip()
        if cfg_arg and cfg_arg.lower() != "none":
            cfg = _load_yaml_config(cfg_arg, _APP_ROOT)
            extra_disabled  = frozenset(cfg.get("disabled_patterns", []))
            yaml_allowlist  = frozenset(cfg.get("allowlist",          []))
            if "mask_style" in cfg:
                effective_mask_style = cfg["mask_style"]
            if "min_confidence" in cfg:
                effective_min_conf = float(cfg["min_confidence"])
            for cp in cfg.get("custom_patterns", []):
                try:
                    extra_patterns.append(Pattern(
                        name=cp["name"],
                        category=cp.get("category", "custom"),
                        regex=re.compile(cp["regex"]),
                        confidence=float(cp.get("confidence", 1.0)),
                    ))
                except Exception as exc:
                    logger.warning("Skipping custom pattern %r: %s", cp.get("name"), exc)

        final_disabled = disabled | extra_disabled
        final_allowlist = ucc_allowlist | lookup_allowlist | yaml_allowlist

        logger.debug(
            "sanitize: standard=%s mask=%s min_conf=%.2f fields=%s",
            effective_standard, effective_mask_style,
            effective_min_conf, effective_fields,
        )

        # ── 5. Process each event ─────────────────────────────────────────────
        for record in records:
            for fld in effective_fields:
                if fld not in record:
                    continue
                result = scrub(
                    str(record[fld]),
                    mask_style=effective_mask_style,
                    disabled_patterns=final_disabled,
                    allowlist=final_allowlist,
                    extra_patterns=extra_patterns,
                    min_confidence=effective_min_conf,
                )
                record[fld] = result.text
                if effective_report and result.findings:
                    record[f"{fld}_findings"]      = ",".join(
                        f.pattern_name for f in result.findings
                    )
                    record[f"{fld}_finding_count"] = str(len(result.findings))
            yield record


dispatch(SanitizeCommand, sys.argv, sys.stdin, sys.stdout, __name__)
