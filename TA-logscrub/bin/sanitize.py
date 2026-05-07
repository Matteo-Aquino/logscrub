#!/usr/bin/env python3
"""
LogScrub  |sanitize  — Splunk streaming search command.

Usage
-----
    ... | sanitize
    ... | sanitize standard=hipaa fields=_raw,message
    ... | sanitize standard=pci  mask_style=full
    ... | sanitize standard=all  configuration=custom.yaml
    ... | sanitize standard=none configuration=strict.yaml  report_findings=false

Parameters
----------
standard        gdpr | hipaa | pci | soc2 | all | none   (default: gdpr)
configuration   <filename.yaml> | none                   (default: none)
fields          comma-separated field names               (default: _raw)
mask_style      partial | full | label | redacted | token (default: partial)
min_confidence  0-100                                     (default: 0)
report_findings true | false                              (default: true)
"""
from __future__ import annotations

import os
import sys

# ── Path setup ─────────────────────────────────────────────────────────────────
# In production the add-on ships logscrub + splunklib inside lib/.
# In development we fall back to the repo root so we always run against the
# live source without copying files.
_HERE     = os.path.dirname(os.path.abspath(__file__))
_APP_ROOT = os.path.dirname(_HERE)           # TA-logscrub/
_LIB      = os.path.join(_APP_ROOT, 'lib')
_REPO_ROOT = os.path.dirname(_APP_ROOT)      # project root (dev only)

sys.path.insert(0, _LIB)        # production: lib/logscrub  +  lib/splunklib
sys.path.insert(0, _REPO_ROOT)  # dev fallback: logscrub/ at repo root

from splunklib.searchcommands import (          # noqa: E402
    dispatch, StreamingCommand, Configuration, Option, validators,
)
from logscrub.engine import scrub               # noqa: E402
from logscrub.patterns import get_patterns, Pattern  # noqa: E402


# ── Built-in compliance standards ─────────────────────────────────────────────
# These are the defaults; admins can override them in default/logscrub.conf.

_BUILTIN_STANDARDS: dict[str, set[str] | None] = {
    "gdpr": {
        # EU personal data
        "email", "phone", "ssn", "us_passport",
        "ipv4", "mac_address",
        "credit_card", "iban",
        "url_credentials", "generic_credential",
    },
    "hipaa": {
        # US healthcare identifiers
        "email", "phone", "ssn", "us_passport",
        "credit_card", "ipv4",
        "url_credentials", "generic_credential",
    },
    "pci": {
        # Payment card data
        "credit_card", "iban",
        "url_credentials", "generic_credential",
    },
    "soc2": {
        # Secrets & credentials
        "jwt", "bearer_token",
        "openai_key", "github_token", "aws_access_key",
        "slack_token", "stripe_key", "google_api_key",
        "anthropic_key", "sendgrid_key",
        "url_credentials", "generic_credential",
    },
    "all":  None,   # None  → every pattern active
    "none": set(),  # empty → nothing runs (use with configuration=)
}


# ── logscrub.conf reader ───────────────────────────────────────────────────────

def _parse_logscrub_conf(app_root: str) -> dict[str, dict[str, str]]:
    """Parse default/logscrub.conf → {stanza: {key: value}}."""
    conf_path = os.path.join(app_root, "default", "logscrub.conf")
    result: dict[str, dict[str, str]] = {}
    current: str | None = None
    if not os.path.exists(conf_path):
        return result
    with open(conf_path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1].lower()
                result.setdefault(current, {})
            elif "=" in line and current is not None:
                k, _, v = line.partition("=")
                result[current][k.strip().lower()] = v.strip()
    return result


def _resolve_allowed(
    standard: str,
    conf: dict[str, dict[str, str]],
) -> set[str] | None:
    """
    Return the set of *allowed* pattern names for *standard*, or None (= all).
    Conf file takes priority over built-in defaults.
    """
    std = standard.lower()
    if std in conf:
        raw = conf[std].get("patterns", "*").strip()
        if raw == "*":
            return None
        return {p.strip() for p in raw.split(",") if p.strip()}
    return _BUILTIN_STANDARDS.get(std, _BUILTIN_STANDARDS["gdpr"])


# ── YAML configuration loader ─────────────────────────────────────────────────

def _load_yaml_config(cfg_arg: str, app_root: str) -> dict:
    """
    Load a YAML config file.  Searches TA-logscrub/lookups/ when a bare
    filename is given; also accepts absolute paths.
    """
    try:
        import yaml
    except ImportError:
        return {}

    path = cfg_arg if os.path.isabs(cfg_arg) else os.path.join(
        app_root, "lookups", cfg_arg
    )
    if not os.path.exists(path):
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

    ##Examples

        index=app_logs | sanitize

        index=app_logs | sanitize standard=hipaa fields=_raw,email

        index=app_logs | sanitize standard=pci mask_style=full

        index=app_logs | sanitize standard=none configuration=custom.yaml
    """

    standard = Option(
        name="standard",
        require=False,
        default="gdpr",
        doc="Compliance standard: gdpr | hipaa | pci | soc2 | all | none  (default: gdpr)",
    )

    configuration = Option(
        name="configuration",
        require=False,
        default="none",
        doc=(
            "YAML config file in TA-logscrub/lookups/ (or absolute path). "
            "Supports: allowlist, disabled_patterns, min_confidence, "
            "mask_style, custom_patterns.  (default: none)"
        ),
    )

    fields = Option(
        name="fields",
        require=False,
        default="_raw",
        doc="Comma-separated fields to scrub.  (default: _raw)",
    )

    mask_style = Option(
        name="mask_style",
        require=False,
        default="partial",
        validate=validators.Set("partial", "full", "label", "redacted", "token"),
        doc="partial | full | label | redacted | token  (default: partial)",
    )

    min_confidence = Option(
        name="min_confidence",
        require=False,
        default=0,
        validate=validators.Integer(minimum=0, maximum=100),
        doc="Only mask patterns with confidence ≥ this value / 100.  (default: 0)",
    )

    report_findings = Option(
        name="report_findings",
        require=False,
        default=True,
        validate=validators.Boolean(),
        doc="Add <field>_findings and <field>_finding_count fields.  (default: true)",
    )

    # ── stream ────────────────────────────────────────────────────────────────

    def stream(self, records):
        # Resolve which patterns are active
        conf    = _parse_logscrub_conf(_APP_ROOT)
        allowed = _resolve_allowed(str(self.standard), conf)
        all_names = {p.name for p in get_patterns()}

        disabled: frozenset[str] = (
            frozenset() if allowed is None else frozenset(all_names - allowed)
        )

        # YAML configuration overrides
        extra_disabled: frozenset[str] = frozenset()
        allowlist:       frozenset[str] = frozenset()
        extra_patterns:  list[Pattern]  = []
        active_mask_style   = str(self.mask_style)
        active_min_conf     = int(self.min_confidence) / 100.0

        cfg_arg = str(self.configuration).strip()
        if cfg_arg.lower() != "none" and cfg_arg:
            cfg = _load_yaml_config(cfg_arg, _APP_ROOT)
            extra_disabled = frozenset(cfg.get("disabled_patterns", []))
            allowlist      = frozenset(cfg.get("allowlist",          []))
            if "mask_style" in cfg:
                active_mask_style = cfg["mask_style"]
            if "min_confidence" in cfg:
                active_min_conf = float(cfg["min_confidence"])
            # Custom patterns defined in the YAML
            for cp in cfg.get("custom_patterns", []):
                try:
                    import re
                    extra_patterns.append(Pattern(
                        name=cp["name"],
                        category=cp.get("category", "custom"),
                        regex=re.compile(cp["regex"]),
                        confidence=float(cp.get("confidence", 1.0)),
                    ))
                except Exception:
                    pass

        final_disabled = disabled | extra_disabled
        target_fields  = [f.strip() for f in str(self.fields).split(",") if f.strip()]

        for record in records:
            for fld in target_fields:
                if fld not in record:
                    continue
                result = scrub(
                    str(record[fld]),
                    mask_style=active_mask_style,
                    disabled_patterns=final_disabled,
                    allowlist=allowlist,
                    extra_patterns=extra_patterns,
                    min_confidence=active_min_conf,
                )
                record[fld] = result.text
                if self.report_findings and result.findings:
                    record[f"{fld}_findings"]      = ",".join(
                        f.pattern_name for f in result.findings
                    )
                    record[f"{fld}_finding_count"] = str(len(result.findings))
            yield record


dispatch(SanitizeCommand, sys.argv, sys.stdin, sys.stdout, __name__)
