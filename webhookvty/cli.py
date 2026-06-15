"""Command-line interface for webhookvty.

Examples
--------
  # Verify a batch of recorded webhooks (CI gate):
  python -m webhookvty verify demos/01-basic/events.json

  # JSON output for piping:
  python -m webhookvty verify demos/01-basic/events.json --format json | jq .

  # Read from stdin:
  cat events.json | python -m webhookvty verify -

Exit codes:
  0  all signatures valid, no replay / idempotency findings
  1  one or more findings (invalid signature, replay, or idempotency bug)
  2  usage / input error
"""
from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import analyze_batch, load_events, DEFAULT_TOLERANCE


def _read_input(path: str) -> str:
    if path == "-":
        try:
            return sys.stdin.read()
        except UnicodeDecodeError as exc:
            raise OSError(f"stdin contains non-UTF-8 data: {exc}") from exc
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except UnicodeDecodeError as exc:
        raise OSError(f"file is not valid UTF-8: {exc}") from exc


def _print_table(report) -> None:
    d = report.to_dict()
    print(f"{TOOL_NAME} {TOOL_VERSION}")
    print("-" * 60)
    print(f"events        : {d['total']}")
    print(f"valid sigs    : {d['valid']}")
    print(f"invalid sigs  : {d['invalid']}")
    print(f"replays       : {len(d['replays'])}")
    print(f"idempotency   : {len(d['idempotency_issues'])}")
    print("-" * 60)
    print(f"{'idx':<4} {'provider':<8} {'event_id':<14} {'valid':<6} reason")
    for r in d["results"]:
        eid = (r["event_id"] or "-")[:14]
        print(
            f"{r['index']:<4} {r['provider']:<8} {eid:<14} "
            f"{('YES' if r['valid'] else 'NO'):<6} {r['reason']}"
        )
    if d["replays"]:
        print("\nREPLAY FINDINGS:")
        for f in d["replays"]:
            print(f"  - {f}")
    if d["idempotency_issues"]:
        print("\nIDEMPOTENCY FINDINGS:")
        for f in d["idempotency_issues"]:
            print(f"  - {f}")
    print("-" * 60)
    print("RESULT: " + ("PASS" if d["ok"] else "FAIL"))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Verify signed payment webhooks (Stripe/Adyen/HMAC) and detect "
            "replay / idempotency bugs. Standard library only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python -m webhookvty verify events.json\n"
            "  python -m webhookvty verify - --format json < events.json\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json"], default="table",
                   help="output format (default: table)")

    sub = p.add_subparsers(dest="command")
    vp = sub.add_parser(
        "verify",
        help="verify a batch of recorded webhook events from a JSON file",
        description="Verify signatures and scan for replay/idempotency bugs.",
    )
    vp.add_argument("input", help="path to JSON file (or '-' for stdin)")
    vp.add_argument("--tolerance", type=int, default=DEFAULT_TOLERANCE,
                    help="timestamp tolerance in seconds for Stripe replay "
                         f"window (default: {DEFAULT_TOLERANCE}; -1 disables)")
    vp.add_argument("--now", type=int, default=None,
                    help="override 'now' (unix ts) for timestamp checks")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 2

    if args.command == "verify":
        if args.tolerance < -1:
            print(
                "error: --tolerance must be -1 (disable) or a non-negative integer",
                file=sys.stderr,
            )
            return 2
        try:
            raw = _read_input(args.input)
        except OSError as exc:
            print(f"error: cannot read input: {exc}", file=sys.stderr)
            return 2
        try:
            events = load_events(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"error: invalid input JSON: {exc}", file=sys.stderr)
            return 2

        report = analyze_batch(events, tolerance=args.tolerance, now=args.now)

        if args.format == "json":
            print(json.dumps(report.to_dict(), indent=2))
        else:
            _print_table(report)

        return 0 if report.ok else 1

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
