"""Table and JSON output."""

from __future__ import annotations

import json
from collections import Counter

from .checks import SEVERITIES, Finding
from .rules import Rule

IMPLIED_NOTE = ("Note: every VPC network also has implied rules at priority 65535 (allow all egress, deny all "
                "ingress) that are not in this export, and hierarchical / network firewall policies are not included.")


def _table(headers: list[str], rows: list[list[str]], wrap_last: int = 0) -> str:
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    fmt = lambda r: "  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip()  # noqa: E731
    return "\n".join([fmt(headers), fmt(["-" * w for w in widths])] + [fmt(r) for r in rows])


def summary(rules: list[Rule], findings: list[Finding]) -> dict:
    c = Counter(f.severity for f in findings)
    return {
        "rules": len(rules),
        "disabled": sum(r.disabled for r in rules),
        "networks": sorted({r.network for r in rules}),
        "findings": {s: c.get(s, 0) for s in reversed(SEVERITIES)},
    }


def rules_table(rules: list[Rule]) -> str:
    rows = []
    for r in sorted(rules, key=lambda r: (r.network, r.direction, r.priority, r.name)):
        if r.ingress:
            src = ", ".join([str(n) for n in r.effective_sources or []] + sorted(f"tag:{t}" for t in r.source_tags)
                            + sorted(f"sa:{s}" for s in r.source_service_accounts))
        else:
            src = "to " + ", ".join(str(n) for n in r.effective_destinations or [])
        tgt = ", ".join(sorted(r.target_tags) + sorted(r.target_service_accounts)) or "(all instances)"
        rows.append([r.network, r.direction, str(r.priority), r.action, r.name, r.ports_label(), src, tgt,
                     "off" if r.disabled else "on", "on" if r.logging else "off"])
    return _table(["NETWORK", "DIR", "PRIO", "ACTION", "RULE", "PROTOCOLS", "SOURCE / DEST", "TARGETS",
                   "ENABLED", "LOGS"], rows)


def render_table(rules: list[Rule], findings: list[Finding], source: str, show_rules: bool = False) -> str:
    s = summary(rules, findings)
    out = [f"Audited {s['rules']} firewall rule(s) ({s['disabled']} disabled) in "
           f"{len(s['networks'])} network(s) from {source}", ""]
    if show_rules:
        out += [rules_table(rules), ""]
    order = sorted(findings, key=lambda f: (-SEVERITIES.index(f.severity), f.network, f.rule, f.code))
    if order:
        out.append(_table(["SEVERITY", "CODE", "RULE", "NETWORK", "DETAIL"],
                          [[f.severity, f.code, f.rule, f.network, f.message] for f in order]))
    else:
        out.append("No findings.")
    out += ["", "Findings: " + ", ".join(f"{v} {k}" for k, v in s["findings"].items()), IMPLIED_NOTE]
    return "\n".join(out)


def render_json(rules: list[Rule], findings: list[Finding]) -> str:
    return json.dumps({"summary": summary(rules, findings),
                       "findings": [f.to_dict() for f in findings]}, indent=2)
