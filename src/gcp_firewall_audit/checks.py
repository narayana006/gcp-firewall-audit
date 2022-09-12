"""Firewall rule checks: exposure, breadth, disabled, logging and shadowing."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

from .rules import IPV4_ANY, IPV6_ANY, Match, Network, Rule

SEVERITIES = ["low", "medium", "high", "critical"]

DEFAULT_SENSITIVE_PORTS: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 445: "smb", 1433: "mssql", 1521: "oracle",
    2375: "docker", 2376: "docker-tls", 2379: "etcd", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5601: "kibana", 5900: "vnc", 6379: "redis", 9200: "elasticsearch", 10250: "kubelet",
    11211: "memcached", 27017: "mongodb",
}
PORT_PROTOCOLS = ("tcp", "udp", "sctp")


@dataclass
class Finding:
    severity: str
    code: str
    rule: str
    network: str
    message: str
    related_rule: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in ("severity", "code", "rule", "network", "related_rule", "message")}


def port_in(m: Match, port: int) -> bool:
    if m.protocol == "all":
        return True
    if m.protocol not in PORT_PROTOCOLS:
        return False
    return m.ports is None or any(a <= port <= b for a, b in m.ports)


def is_all_ports(m: Match) -> bool:
    if m.protocol == "all":
        return True
    if m.protocol not in PORT_PROTOCOLS:
        return False
    return m.ports is None or _merged(m.ports) == [(0, 65535)]


def exposure_checks(r: Rule, sensitive: dict[int, str]) -> list[Finding]:
    out: list[Finding] = []
    if r.disabled or r.action != "allow" or not r.ingress:
        return out
    public = r.public_sources
    srcs = ", ".join(str(n) for n in public)
    add = lambda sev, code, msg: out.append(Finding(sev, code, r.name, r.network, msg))  # noqa: E731
    broad = [m for m in r.matches if is_all_ports(m)]
    if public:
        if broad:
            add("critical", "INTERNET_ALL_PORTS", f"allows {' '.join(m.label() for m in broad)} from {srcs}")
        else:
            hits = sorted({f"{p}/{sensitive[p]}" for p in sensitive for m in r.matches if port_in(m, p)},
                          key=lambda s: int(s.split("/")[0]))
            if hits:
                add("high", "INTERNET_SENSITIVE_PORT", f"allows {', '.join(hits)} from {srcs}")
            else:
                add("low", "INTERNET_EXPOSED", f"allows {r.ports_label()} from {srcs}")
        if r.applies_to_all_instances:
            add("medium", "NO_TARGETS", "internet-exposed rule has no target tags or service accounts, "
                "so it applies to every instance in the network")
        if not r.logging:
            add("low", "NO_LOGGING", "firewall rules logging is off for an internet-exposed rule")
    else:
        if broad:
            add("medium", "ALL_PORTS", f"allows {' '.join(m.label() for m in broad)} (every port) "
                f"from {_source_label(r)}")
        if r.applies_to_all_instances:
            add("low", "NO_TARGETS", "no target tags or service accounts; applies to every instance in the network")
    return out


def _source_label(r: Rule) -> str:
    parts = [str(n) for n in r.source_ranges]
    parts += [f"tag:{t}" for t in sorted(r.source_tags)]
    parts += [f"sa:{s}" for s in sorted(r.source_service_accounts)]
    return ", ".join(parts) or "any source"


# ---- shadowing -------------------------------------------------------------

def _ranges_cover(a: Optional[list[Network]], b: Optional[list[Network]]) -> bool:
    """None means unrestricted. Each range of b must sit inside one range of a."""
    if a is None:
        return True
    if b is None:
        return False
    return all(any(nb.version == na.version and nb.subnet_of(na) for na in a) for nb in b)


def _targets_cover(a: Rule, b: Rule) -> bool:
    if a.applies_to_all_instances:
        return True
    if b.applies_to_all_instances:
        return False
    if a.target_tags and b.target_tags:
        return b.target_tags <= a.target_tags
    if a.target_service_accounts and b.target_service_accounts:
        return b.target_service_accounts <= a.target_service_accounts
    return False


def _sources_cover(a: Rule, b: Rule) -> bool:
    if not b.ingress:
        return _ranges_cover(a.effective_sources, b.effective_sources)
    a_ip, b_ip = a.effective_sources or [], b.effective_sources or []
    if not _ranges_cover(a_ip, b_ip):
        return False
    if not (b.source_tags or b.source_service_accounts):
        return True
    # Tag / service-account sources are only treated as covered by the same
    # identities, or by a rule that allows every IPv4 and IPv6 address.
    if IPV4_ANY in a_ip and IPV6_ANY in a_ip:
        return True
    return b.source_tags <= a.source_tags and b.source_service_accounts <= a.source_service_accounts


def _merged(ranges: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[list[int]] = []
    for lo, hi in sorted(ranges):
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return [(a, b) for a, b in out]


def _protocols_cover(a: Rule, b: Rule) -> bool:
    if any(m.protocol == "all" for m in a.matches):
        return True
    for mb in b.matches:
        if mb.protocol == "all":
            return False
        same = [m for m in a.matches if m.protocol == mb.protocol]
        if not same:
            return False
        if any(m.ports is None for m in same):
            continue
        if mb.ports is None:
            return False
        merged = _merged(r for m in same for r in m.ports)
        if not all(any(x <= lo and hi <= y for x, y in merged) for lo, hi in mb.ports):
            return False
    return True


def covers(a: Rule, b: Rule) -> bool:
    """True if every packet rule b matches is also matched by rule a."""
    return (a.network == b.network and a.direction == b.direction
            and _targets_cover(a, b) and _sources_cover(a, b)
            and _ranges_cover(a.effective_destinations, b.effective_destinations)
            and _protocols_cover(a, b))


def takes_precedence(a: Rule, b: Rule) -> bool:
    """Lower priority number wins; at equal priority a deny beats an allow."""
    return a.priority < b.priority or (a.priority == b.priority and a.action == "deny" and b.action == "allow")


def shadow_checks(rules: list[Rule]) -> list[Finding]:
    out = []
    active = sorted((r for r in rules if not r.disabled), key=lambda r: (r.priority, r.action != "deny"))
    for b in active:
        for a in active:
            if a is b or not takes_precedence(a, b) or not covers(a, b):
                continue
            if a.action == b.action:
                out.append(Finding("low", "REDUNDANT", b.name, b.network,
                                   f"fully covered by {a.name} (priority {a.priority}, also {a.action}); "
                                   f"{b.name} (priority {b.priority}) never decides any traffic", a.name))
            else:
                effect = ("never allows anything" if b.action == "allow"
                          else "never blocks anything; that traffic is allowed")
                out.append(Finding("medium", "SHADOWED", b.name, b.network,
                                   f"{a.action} rule {a.name} (priority {a.priority}) covers all of its traffic, "
                                   f"so this {b.action} rule (priority {b.priority}) {effect}", a.name))
            break
    return out


def audit(rules: list[Rule], sensitive: dict[int, str] | None = None,
          ignore: Iterable[str] = ()) -> list[Finding]:
    sensitive = DEFAULT_SENSITIVE_PORTS if sensitive is None else sensitive
    findings: list[Finding] = []
    for r in rules:
        if r.disabled:
            findings.append(Finding("low", "DISABLED", r.name, r.network,
                                    f"rule is disabled (not enforced); {r.action} {r.ports_label()}"))
        findings.extend(exposure_checks(r, sensitive))
    findings.extend(shadow_checks(rules))
    skip = {c.upper() for c in ignore}
    return [f for f in findings if f.code not in skip]


def severity_at_least(sev: str, threshold: str) -> bool:
    return SEVERITIES.index(sev) >= SEVERITIES.index(threshold)
