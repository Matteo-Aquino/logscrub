"""
Audit log export for datascrub.

Generates CSV or JSON reports of all findings from a scrub session, suitable
for handing to a legal or compliance team.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from .engine import ScrubResult


_FIELDS = ("timestamp", "source", "pattern", "category", "confidence",
           "original", "masked", "char_offset")


def build_report(
    results: list[tuple[str, ScrubResult]],
    *,
    include_original: bool = True,
) -> dict:
    """Build a structured de-identification report dict.

    Parameters
    ----------
    results:
        List of (source_label, ScrubResult) pairs — one per file or input chunk.
    include_original:
        Whether to include the original (pre-mask) values in the report.
        Set to False when sharing the report externally.
    """
    ts = datetime.now(tz=timezone.utc).isoformat()
    total = sum(r.finding_count for _, r in results)

    summary: dict[str, int] = {}
    for _, r in results:
        for cat, count in r.summary_by_category().items():
            summary[cat] = summary.get(cat, 0) + count

    findings_out = []
    for source, result in results:
        for f in result.findings:
            entry: dict = {
                "timestamp": ts,
                "source": source,
                "pattern": f.pattern_name,
                "category": f.category,
                "confidence": f.confidence,
                "masked": f.masked,
                "char_offset": f.start,
            }
            if include_original:
                entry["original"] = f.original
            findings_out.append(entry)

    return {
        "generated_at": ts,
        "total_findings": total,
        "summary_by_category": summary,
        "findings": findings_out,
    }


def export_json(
    results: list[tuple[str, ScrubResult]],
    path: str | Path,
    *,
    include_original: bool = True,
) -> None:
    """Write the report as a pretty-printed JSON file."""
    report = build_report(results, include_original=include_original)
    Path(path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def export_csv(
    results: list[tuple[str, ScrubResult]],
    path: str | Path,
    *,
    include_original: bool = True,
) -> None:
    """Write the report as a flat CSV file."""
    fields = list(_FIELDS)
    if not include_original:
        fields = [f for f in fields if f != "original"]

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()

    report = build_report(results, include_original=include_original)
    writer.writerows(report["findings"])

    Path(path).write_text(buf.getvalue(), encoding="utf-8")


def export_text(
    results: list[tuple[str, ScrubResult]],
    *,
    include_original: bool = False,
) -> str:
    """Return a human-readable plain-text de-identification report."""
    report = build_report(results, include_original=include_original)
    lines = [
        "=" * 60,
        "  DATASCRUB DE-IDENTIFICATION REPORT",
        f"  Generated: {report['generated_at']}",
        "=" * 60,
        f"  Total findings : {report['total_findings']}",
    ]
    for cat, count in sorted(report["summary_by_category"].items()):
        lines.append(f"    {cat:<20} {count}")
    lines += ["", "  FINDINGS", "-" * 60]
    for f in report["findings"]:
        conf_pct = f"{f['confidence'] * 100:.0f}%"
        orig = f"  original: {f['original']!r}" if include_original else ""
        lines.append(
            f"  [{f['pattern']}] ({f['category']}, conf={conf_pct})"
            f"  →  {f['masked']!r}{orig}"
            f"  @ {f['source']}+{f['char_offset']}"
        )
    lines.append("=" * 60)
    return "\n".join(lines)
