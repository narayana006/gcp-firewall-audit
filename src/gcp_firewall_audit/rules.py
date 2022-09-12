"""Load VPC firewall rules (``gcloud compute firewall-rules list --format=json``)
and normalise them for analysis.

Semantics follow the Compute Engine ``Firewall`` resource: priority 0-65535
(default 1000, lower number wins), direction INGRESS (default) or EGRESS, an
``allowed`` or ``denied`` list of ``{IPProtocol, ports}``, and a rule with
neither target tags nor target service accounts applies to every instance in
the network. An ingress rule with no source uses 0.0.0.0/0 (IPv4 only).
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from typing import Any, Optional

ALL_PORTS = None  # sentinel: protocol matches on every port
PROTO_NUMBERS = {"1": "icmp", "4": "ipip", "6": "tcp", "17": "udp", "50": "esp", "51": "ah", "132": "sctp"}
IPV4_ANY = ipaddress.ip_network("0.0.0.0/0")
IPV6_ANY = ipaddress.ip_network("::/0")

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class Match:
    """One allowed/denied entry. ``ports`` is None for 'all ports'."""
    protocol: str  # tcp, udp, icmp, ..., or "all"
    ports: Optional[tuple[tuple[int, int], ...]]

    def label(self) -> str:
        if self.protocol == "all":
            return "all"
        if self.ports is None:
            return self.protocol
        return ",".join(f"{self.protocol}:{a}" if a == b else f"{self.protocol}:{a}-{b}" for a, b in self.ports)


@dataclass
class Rule:
    name: str
    network: str
    priority: int
    direction: str
    action: str  # allow | deny
    matches: list[Match]
    source_ranges: list[Network] = field(default_factory=list)
    destination_ranges: list[Network] = field(default_factory=list)
    source_tags: frozenset[str] = frozenset()
    source_service_accounts: frozenset[str] = frozenset()
    target_tags: frozenset[str] = frozenset()
    target_service_accounts: frozenset[str] = frozenset()
    disabled: bool = False
    logging: bool = False
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def ingress(self) -> bool:
        return self.direction == "INGRESS"

    @property
    def applies_to_all_instances(self) -> bool:
        return not self.target_tags and not self.target_service_accounts

    @property
    def effective_sources(self) -> Optional[list[Network]]:
        """Source ranges in effect; None means 'not restricted by IP'."""
        if self.ingress and not (self.source_ranges or self.source_tags or self.source_service_accounts):
            return [IPV4_ANY]
        return self.source_ranges or (None if not self.ingress else [])

    @property
    def effective_destinations(self) -> Optional[list[Network]]:
        if not self.ingress and not self.destination_ranges:
            return [IPV4_ANY]
        return self.destination_ranges or None

    @property
    def public_sources(self) -> list[Network]:
        if not self.ingress:
            return []
        return [n for n in (self.effective_sources or []) if n.prefixlen == 0]

    def ports_label(self) -> str:
        return " ".join(m.label() for m in self.matches)


def short_network(url: str) -> str:
    """'https://.../projects/p/global/networks/n' -> 'p/n'; 'global/networks/n' -> 'n'."""
    parts = url.rstrip("/").split("/")
    if "networks" in parts:
        name = parts[parts.index("networks") + 1] if parts.index("networks") + 1 < len(parts) else ""
        if "projects" in parts:
            return f"{parts[parts.index('projects') + 1]}/{name}"
        return name
    return url


def parse_ports(ports: list[Any] | None, rule: str) -> Optional[tuple[tuple[int, int], ...]]:
    if not ports:
        return ALL_PORTS
    out = []
    for p in ports:
        s = str(p).strip()
        try:
            lo, _, hi = s.partition("-")
            a, b = int(lo), int(hi or lo)
        except ValueError:
            raise RuleError(f"rule {rule}: bad port {s!r}") from None
        if not (0 <= a <= b <= 65535):
            raise RuleError(f"rule {rule}: bad port range {s!r}")
        out.append((a, b))
    return tuple(sorted(out))


def _net(s: str, rule: str) -> Network:
    try:
        return ipaddress.ip_network(s.strip(), strict=False)
    except ValueError:
        raise RuleError(f"rule {rule}: bad CIDR {s!r}") from None


def parse_rule(obj: dict[str, Any]) -> Rule:
    if not isinstance(obj, dict) or "name" not in obj:
        raise RuleError("each firewall rule must be an object with a 'name'")
    name = obj["name"]
    if obj.get("allowed") and obj.get("denied"):
        raise RuleError(f"rule {name}: has both 'allowed' and 'denied'")
    action = "deny" if obj.get("denied") else "allow"
    entries = obj.get("denied") or obj.get("allowed") or []
    if not entries:
        raise RuleError(f"rule {name}: has neither 'allowed' nor 'denied'")
    matches = []
    for e in entries:
        proto = str(e.get("IPProtocol", "")).lower()
        proto = PROTO_NUMBERS.get(proto, proto)
        if not proto:
            raise RuleError(f"rule {name}: entry without IPProtocol")
        ports = ALL_PORTS if proto == "all" else parse_ports(e.get("ports"), name)
        matches.append(Match(proto, ports))
    direction = str(obj.get("direction") or "INGRESS").upper()
    if direction not in ("INGRESS", "EGRESS"):
        raise RuleError(f"rule {name}: unknown direction {direction!r}")
    priority = int(obj.get("priority", 1000))
    if not 0 <= priority <= 65535:
        raise RuleError(f"rule {name}: priority {priority} outside 0-65535")
    return Rule(
        name=name,
        network=short_network(obj.get("network") or "global/networks/default"),
        priority=priority,
        direction=direction,
        action=action,
        matches=matches,
        source_ranges=[_net(s, name) for s in obj.get("sourceRanges") or []],
        destination_ranges=[_net(s, name) for s in obj.get("destinationRanges") or []],
        source_tags=frozenset(obj.get("sourceTags") or []),
        source_service_accounts=frozenset(obj.get("sourceServiceAccounts") or []),
        target_tags=frozenset(obj.get("targetTags") or []),
        target_service_accounts=frozenset(obj.get("targetServiceAccounts") or []),
        disabled=bool(obj.get("disabled", False)),
        logging=bool((obj.get("logConfig") or {}).get("enable", False)),
        raw=obj,
    )


def load_rules(text: str, source: str = "<input>") -> list[Rule]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuleError(f"{source}: not valid JSON ({exc}); use --format=json with gcloud") from exc
    if isinstance(data, dict):
        data = data.get("items", [data]) if "name" not in data else [data]
    if not isinstance(data, list):
        raise RuleError(f"{source}: expected a JSON list of firewall rules")
    return [parse_rule(r) for r in data]
