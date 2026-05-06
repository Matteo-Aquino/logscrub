"""
datascrub command-line interface.

Usage
-----
  datascrub scrub input.txt [-o output.txt] [--profile HIPAA] [--dry-run]
  datascrub scrub input.json --format json --mask-style token --token-map map.json
  datascrub batch src/ dst/ [--audit report.json] [--dry-run]
  datascrub gui                        # launch the desktop GUI
  datascrub profiles                   # list available profiles

Exit codes: 0 = success, 1 = user error, 2 = I/O error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import NoReturn


# ── Helpers ────────────────────────────────────────────────────────────────────

def _die(msg: str, code: int = 1) -> NoReturn:
    print(f"datascrub: {msg}", file=sys.stderr)
    sys.exit(code)


def _build_scrub_kwargs(args: argparse.Namespace) -> dict:
    """Translate CLI args into keyword arguments accepted by scrub/scrub_json/scrub_csv."""
    from .profiles import get_profile, load_profile_from_path

    kwargs: dict = {
        "mask_style": args.mask_style or "partial",
        "mask_char": args.mask_char or "*",
        "disabled_patterns": frozenset(args.disable or []),
        "allowlist": frozenset(args.allowlist or []),
        "min_confidence": args.min_confidence,
    }

    # Profile overrides defaults; explicit flags override the profile
    if args.profile:
        p = None
        path = Path(args.profile)
        if path.exists():
            p = load_profile_from_path(path)
        else:
            p = get_profile(args.profile)
        if p is None:
            _die(f"profile not found: {args.profile!r}")
        # Apply profile values only when the flag was not explicitly provided
        if args.mask_style is None:
            kwargs["mask_style"] = p.mask_style
        if args.mask_char is None:
            kwargs["mask_char"] = p.mask_char
        if not args.disable:
            kwargs["disabled_patterns"] = frozenset(p.disabled_patterns)
        if not args.allowlist:
            kwargs["allowlist"] = frozenset(p.allowlist)

    return kwargs


def _detect_format(path: Path, hint: str) -> str:
    if hint != "auto":
        return hint
    return {".json": "json", ".csv": "csv"}.get(path.suffix.lower(), "text")


def _load_token_map(path: str | None) -> dict:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        _die(f"cannot read token map {path!r}: {exc}", 2)


def _save_token_map(token_map: dict, path: str) -> None:
    try:
        Path(path).write_text(json.dumps(token_map, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        print(f"datascrub: warning — could not save token map: {exc}", file=sys.stderr)


# ── scrub subcommand ───────────────────────────────────────────────────────────

def cmd_scrub(args: argparse.Namespace) -> None:
    from .engine import scrub
    from .handlers import scrub_json, scrub_csv

    # Read input
    if args.input == "-":
        text = sys.stdin.read()
        fmt = _detect_format(Path("stdin.txt"), args.format)
        source_name = "<stdin>"
    else:
        p = Path(args.input)
        if not p.exists():
            _die(f"input file not found: {args.input!r}", 2)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _die(f"cannot read {args.input!r}: {exc}", 2)
        fmt = _detect_format(p, args.format)
        source_name = p.name

    token_map = _load_token_map(args.token_map)
    kwargs = _build_scrub_kwargs(args)
    kwargs["token_map"] = token_map

    # Run scrub
    scrub_fn = {"json": scrub_json, "csv": scrub_csv}.get(fmt, scrub)
    result = scrub_fn(text, **kwargs)

    # Dry-run: show findings summary only, no output written
    if args.dry_run:
        print(f"[dry-run] {source_name}: {result.finding_count} finding(s) would be masked")
        for f in result.findings:
            conf = f"{f.confidence * 100:.0f}%"
            print(f"  {f.pattern_name:<20} {conf:<5} {f.original[:60]!r}")
        return

    # Write output
    if args.output and args.output != "-":
        try:
            Path(args.output).write_text(result.text, encoding="utf-8")
        except OSError as exc:
            _die(f"cannot write {args.output!r}: {exc}", 2)
    else:
        sys.stdout.write(result.text)

    # Persist token map if requested
    if args.token_map and token_map is not None:
        _save_token_map(token_map, args.token_map)

    # Audit log
    if args.audit:
        _write_audit(args.audit, [(source_name, result)])

    # Stats to stderr
    if not args.quiet:
        print(
            f"{source_name}: {result.finding_count} finding(s) masked  "
            f"[{fmt}, {args.mask_style}]",
            file=sys.stderr,
        )


# ── batch subcommand ───────────────────────────────────────────────────────────

def cmd_batch(args: argparse.Namespace) -> None:
    from .engine import scrub
    from .handlers import scrub_json, scrub_csv

    src = Path(args.src)
    dst = Path(args.dst)
    if not src.is_dir():
        _die(f"source is not a directory: {args.src!r}", 2)

    exts = {".txt", ".json", ".csv", ".log", ".yaml", ".yml", ".xml", ".md", ".env"}
    paths = [p for p in src.rglob("*") if p.is_file() and p.suffix.lower() in exts]
    if not paths:
        print("datascrub: no supported files found.", file=sys.stderr)
        return

    token_map = _load_token_map(args.token_map)
    kwargs = _build_scrub_kwargs(args)
    kwargs["token_map"] = token_map

    all_results = []
    total = 0
    errors = 0

    for path in sorted(paths):
        rel = path.relative_to(src)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"  ✗  {rel}: {exc}", file=sys.stderr)
            errors += 1
            continue

        fmt = _detect_format(path, "auto")
        scrub_fn = {"json": scrub_json, "csv": scrub_csv}.get(fmt, scrub)
        result = scrub_fn(text, **kwargs)

        if args.dry_run:
            print(f"  [dry-run] {rel}: {result.finding_count} finding(s)")
        else:
            out = dst / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            try:
                out.write_text(result.text, encoding="utf-8")
            except OSError as exc:
                print(f"  ✗  {rel}: write error: {exc}", file=sys.stderr)
                errors += 1
                continue

        total += result.finding_count
        all_results.append((str(path), result))
        if not args.quiet:
            action = "[dry-run]" if args.dry_run else "✓"
            print(f"  {action}  {rel}  ({result.finding_count} findings)")

    action = "would mask" if args.dry_run else "masked"
    print(f"\nDone: {len(all_results)} files, {total} findings {action}. "
          f"{f'{errors} error(s).' if errors else ''}")

    if args.token_map and not args.dry_run:
        _save_token_map(token_map, args.token_map)

    if args.audit and all_results and not args.dry_run:
        _write_audit(args.audit, all_results)


# ── profiles subcommand ────────────────────────────────────────────────────────

def cmd_profiles(args: argparse.Namespace) -> None:
    from .profiles import list_profiles
    profiles = list_profiles()
    if not profiles:
        print("No profiles found.")
        return
    for p in profiles:
        disabled = f"  disabled: {', '.join(p.disabled_patterns)}" if p.disabled_patterns else ""
        desc = f"  # {p.description}" if p.description else ""
        print(f"  {p.name:<20} style={p.mask_style:<10} char={p.mask_char!r}{disabled}{desc}")


# ── audit helper ───────────────────────────────────────────────────────────────

def _write_audit(path: str, results: list) -> None:
    from .audit import export_json as audit_json, export_csv as audit_csv
    p = Path(path)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.suffix.lower() == ".csv":
            audit_csv(results, p)
        else:
            audit_json(results, p)
        print(f"Audit log: {path}", file=sys.stderr)
    except Exception as exc:
        print(f"datascrub: warning — audit write failed: {exc}", file=sys.stderr)


# ── GUI launcher ───────────────────────────────────────────────────────────────

def cmd_gui(args: argparse.Namespace) -> None:
    from .gui.app import main
    main()


# ── Argument parser ────────────────────────────────────────────────────────────

def _make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="datascrub",
        description="Detect and mask sensitive data in text, JSON, and CSV files.",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── shared scrub flags ─────────────────────────────────────────────────────
    def _add_scrub_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument("--profile", metavar="NAME_OR_PATH",
                       help="Apply a named or file-path profile (JSON/YAML).")
        p.add_argument("--mask-style",
                       choices=["partial", "label", "full", "redacted", "token"],
                       default=None, dest="mask_style")
        p.add_argument("--mask-char", default=None, metavar="CHAR", dest="mask_char")
        p.add_argument("--disable", nargs="+", metavar="PATTERN",
                       help="Pattern names to disable (e.g. --disable ipv4 phone).")
        p.add_argument("--allowlist", nargs="+", metavar="VALUE",
                       help="Literal values to never mask.")
        p.add_argument("--min-confidence", type=float, default=0.0,
                       dest="min_confidence", metavar="0.0-1.0",
                       help="Skip findings below this confidence threshold.")
        p.add_argument("--token-map", metavar="PATH", dest="token_map",
                       help="JSON file to read/write the token → value map (for --mask-style token).")
        p.add_argument("--audit", metavar="PATH",
                       help="Write an audit log to this path (.json or .csv).")
        p.add_argument("--dry-run", action="store_true", dest="dry_run",
                       help="Print findings without writing any output.")
        p.add_argument("-q", "--quiet", action="store_true",
                       help="Suppress progress output to stderr.")

    # ── scrub ──────────────────────────────────────────────────────────────────
    sp = sub.add_parser("scrub", help="Scrub a single file or stdin.")
    sp.add_argument("input", nargs="?", default="-",
                    help="Input file path, or '-' for stdin (default).")
    sp.add_argument("-o", "--output", metavar="PATH",
                    help="Output file path, or '-' for stdout (default).")
    sp.add_argument("--format", choices=["auto", "text", "json", "csv"], default="auto",
                    help="Force input format (default: auto-detect from extension).")
    _add_scrub_flags(sp)
    sp.set_defaults(func=cmd_scrub)

    # ── batch ──────────────────────────────────────────────────────────────────
    bp = sub.add_parser("batch", help="Scrub all supported files in a directory tree.")
    bp.add_argument("src", help="Source directory.")
    bp.add_argument("dst", help="Output directory (mirrors source tree).")
    _add_scrub_flags(bp)
    bp.set_defaults(func=cmd_batch)

    # ── profiles ───────────────────────────────────────────────────────────────
    pp = sub.add_parser("profiles", help="List available profiles.")
    pp.set_defaults(func=cmd_profiles)

    # ── gui ────────────────────────────────────────────────────────────────────
    gp = sub.add_parser("gui", help="Launch the desktop GUI.")
    gp.set_defaults(func=cmd_gui)

    return parser


# ── Entry point ────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> None:
    import os
    os.environ.setdefault("PYTHONUTF8", "1")

    parser = _make_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        # No subcommand → launch GUI (makes `datascrub` with no args useful)
        from .gui.app import main as gui_main
        gui_main()
        return

    args.func(args)
