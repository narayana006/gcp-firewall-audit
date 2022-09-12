"""Command line entry point."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .checks import DEFAULT_SENSITIVE_PORTS, audit, severity_at_least
from .report import render_json, render_table
from .rules import RuleError, load_rules


def parse_port_list(text: str) -> dict[int, str]:
    out = {}
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        port, _, label = item.partition("/")
        try:
            n = int(port)
        except ValueError:
            raise argparse.ArgumentTypeError(f"bad port {item!r} (use 22 or 22/ssh)") from None
        if not 0 <= n <= 65535:
            raise argparse.ArgumentTypeError(f"port {n} outside 0-65535")
        out[n] = label or DEFAULT_SENSITIVE_PORTS.get(n, "custom")
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gcp-firewall-audit",
        description="Audit VPC firewall rules from `gcloud compute firewall-rules list --format=json`. "
                    "Offline: reads files or stdin, never calls Google Cloud.",
    )
    p.add_argument("files", nargs="*", default=["-"], help="rule JSON files, or - for stdin (default)")
    p.add_argument("--format", choices=["table", "json"], default="table")
    p.add_argument("--sensitive-ports", type=parse_port_list, metavar="LIST",
                   help="replace the sensitive port list, e.g. 22/ssh,3389/rdp,8080")
    p.add_argument("--add-sensitive-ports", type=parse_port_list, metavar="LIST",
                   help="add ports to the default sensitive list")
    p.add_argument("--network", action="append", default=[], metavar="NAME",
                   help="only audit this network (name or project/name; repeatable)")
    p.add_argument("--ignore", action="append", default=[], metavar="CODE", help="skip a finding code (repeatable)")
    p.add_argument("--fail-on", choices=["low", "medium", "high", "critical", "never"], default="high",
                   help="exit 1 if a finding is at or above this severity (default high)")
    p.add_argument("--show-rules", action="store_true", help="table output: also print the normalised rule list")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    rules = []
    try:
        for path in args.files:
            if path == "-":
                rules += load_rules(sys.stdin.read(), "<stdin>")
            else:
                with open(path, encoding="utf-8") as fh:
                    rules += load_rules(fh.read(), path)
    except (OSError, RuleError) as exc:
        print(f"gcp-firewall-audit: error: {exc}", file=sys.stderr)
        return 2
    if args.network:
        wanted = set(args.network)
        rules = [r for r in rules if r.network in wanted or r.network.split("/")[-1] in wanted]

    sensitive = dict(args.sensitive_ports if args.sensitive_ports is not None else DEFAULT_SENSITIVE_PORTS)
    sensitive.update(args.add_sensitive_ports or {})
    findings = audit(rules, sensitive, args.ignore)

    if args.format == "json":
        print(render_json(rules, findings))
    else:
        print(render_table(rules, findings, ", ".join("<stdin>" if f == "-" else f for f in args.files),
                           args.show_rules))
    if args.fail_on != "never" and any(severity_at_least(f.severity, args.fail_on) for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
