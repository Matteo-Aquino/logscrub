#!/usr/bin/env python3
"""
LogScrub alert action — logscrub_alert.py

Triggered when a saved search fires. Reads alert results, scrubs specified
fields using the LogScrub engine, then writes scrubbed events to a summary
index via the Splunk SDK.

Splunk passes a JSON settings file path as sys.argv[1].
"""
from __future__ import annotations

import csv
import io
import json
import logging
import os
import sys

# ── Path setup ─────────────────────────────────────────────────────────────────
_HERE     = os.path.dirname(os.path.abspath(__file__))
_APP_ROOT = os.path.dirname(_HERE)
_LIB      = os.path.join(_APP_ROOT, 'lib')
_REPO_ROOT = os.path.dirname(os.path.dirname(_APP_ROOT))

sys.path.insert(0, _LIB)
sys.path.insert(0, _REPO_ROOT)

from logscrub.engine import scrub  # noqa: E402

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s level=%(levelname)s action=logscrub_sanitize %(message)s',
    stream=sys.stderr,
)
logger = logging.getLogger('logscrub.alert')

# ── Pattern sets (mirrors sanitize.py) ───────────────────────────────────────
_STANDARDS: dict[str, set[str] | None] = {
    "gdpr":  {"email","phone","ssn","us_passport","ipv4","mac_address","credit_card","iban","url_credentials","generic_credential"},
    "hipaa": {"email","phone","ssn","us_passport","credit_card","ipv4","url_credentials","generic_credential"},
    "pci":   {"credit_card","iban","url_credentials","generic_credential"},
    "soc2":  {"jwt","bearer_token","openai_key","github_token","aws_access_key","slack_token","stripe_key","google_api_key","anthropic_key","sendgrid_key","url_credentials","generic_credential"},
    "all":   None,
    "none":  set(),
}


def _load_settings(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        logger.error("Cannot read settings file %s: %s", path, exc)
        return {}


def _read_results_csv(results_file: str) -> list[dict]:
    try:
        with open(results_file, encoding="utf-8", newline="") as fh:
            return list(csv.DictReader(fh))
    except Exception as exc:
        logger.error("Cannot read results file %s: %s", results_file, exc)
        return []


def _write_results_csv(rows: list[dict], fields: list[str]) -> str:
    """Serialise rows back to CSV string for collection."""
    buf = io.StringIO()
    all_keys = list({k for r in rows for k in r})
    writer = csv.DictWriter(buf, fieldnames=all_keys, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def main() -> None:
    if len(sys.argv) < 2:
        logger.error("Usage: logscrub_alert.py <settings.json>")
        sys.exit(1)

    settings = _load_settings(sys.argv[1])
    config   = settings.get("configuration", {})
    results_file = settings.get("results_file", "")

    # ── Parameters from alert action config ────────────────────────────────────
    fields_raw     = config.get("fields",          "_raw")
    standard       = config.get("standard",        "gdpr").lower()
    mask_style     = config.get("mask_style",      "partial")
    summary_index  = config.get("summary_index",   "logscrub_findings")
    report_findings = str(config.get("report_findings", "1")) == "1"

    target_fields = [f.strip() for f in fields_raw.split(",") if f.strip()]

    # ── Resolve disabled patterns from standard ────────────────────────────────
    from logscrub.patterns import get_patterns
    all_names = {p.name for p in get_patterns()}
    allowed   = _STANDARDS.get(standard, _STANDARDS["gdpr"])
    disabled  = frozenset() if allowed is None else frozenset(all_names - allowed)

    # ── Read alert results ─────────────────────────────────────────────────────
    rows = _read_results_csv(results_file)
    if not rows:
        logger.info("No results to process.")
        return

    logger.info(
        "Processing %d events — standard=%s mask=%s fields=%s → index=%s",
        len(rows), standard, mask_style, target_fields, summary_index,
    )

    # ── Scrub each row ─────────────────────────────────────────────────────────
    scrubbed_rows: list[dict] = []
    total_findings = 0
    for row in rows:
        new_row = dict(row)
        for fld in target_fields:
            if fld not in new_row:
                continue
            result = scrub(
                str(new_row[fld]),
                mask_style=mask_style,
                disabled_patterns=disabled,
            )
            new_row[fld] = result.text
            if report_findings and result.findings:
                new_row[f"{fld}_findings"]      = ",".join(f.pattern_name for f in result.findings)
                new_row[f"{fld}_finding_count"] = str(len(result.findings))
                total_findings += len(result.findings)
        scrubbed_rows.append(new_row)

    logger.info("Scrubbed %d finding(s) across %d event(s).", total_findings, len(scrubbed_rows))

    # ── Write to summary index via Splunk SDK ──────────────────────────────────
    try:
        import splunklib.client as client

        session_key = settings.get("session_key", "")
        splunk      = client.connect(
            token=session_key,
            host="localhost",
            port=8089,
        )
        index = splunk.indexes[summary_index]

        for row in scrubbed_rows:
            event_text = " ".join(f'{k}="{v}"' for k, v in row.items() if v)
            index.submit(event_text, sourcetype="logscrub:findings", host="logscrub_alert")

        logger.info("Collected %d scrubbed event(s) to index=%s.", len(scrubbed_rows), summary_index)

    except Exception as exc:
        logger.error("Failed to collect to summary index: %s", exc)
        # Write scrubbed CSV to stdout as fallback so Splunk can log it
        print(_write_results_csv(scrubbed_rows, target_fields))
        sys.exit(1)


if __name__ == "__main__":
    main()
