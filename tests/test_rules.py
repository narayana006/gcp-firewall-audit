import ipaddress

import pytest
from helpers import mk

from gcp_firewall_audit.rules import RuleError, load_rules, parse_rule, short_network


def test_defaults_match_api_semantics():
    r = parse_rule({"name": "x", "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]})
    assert r.priority == 1000 and r.direction == "INGRESS" and r.action == "allow"
    assert r.network == "default"
    assert not r.disabled and not r.logging
    # ingress with no source at all -> 0.0.0.0/0 (IPv4 only)
    assert r.effective_sources == [ipaddress.ip_network("0.0.0.0/0")]
    assert r.applies_to_all_instances


def test_tag_only_source_has_no_ip_ranges():
    r = mk(sourceTags=["web"])
    assert r.effective_sources == []
    assert r.public_sources == []


def test_egress_default_destination():
    r = mk(direction="EGRESS", denied=[{"IPProtocol": "tcp", "ports": ["25"]}])
    assert r.action == "deny"
    assert r.effective_destinations == [ipaddress.ip_network("0.0.0.0/0")]
    assert r.public_sources == []


def test_ports_and_protocol_numbers():
    r = mk(allowed=[{"IPProtocol": "6", "ports": ["443", "8000-8080"]}, {"IPProtocol": "ICMP"},
                    {"IPProtocol": "all"}])
    assert [m.protocol for m in r.matches] == ["tcp", "icmp", "all"]
    assert r.matches[0].ports == ((443, 443), (8000, 8080))
    assert r.matches[1].ports is None
    assert r.ports_label() == "tcp:443,tcp:8000-8080 icmp all"


def test_logging_from_logconfig():
    assert mk(logConfig={"enable": True}).logging
    assert not mk(logConfig={"enable": False}).logging


def test_short_network():
    assert short_network("https://www.googleapis.com/compute/v1/projects/p1/global/networks/n1") == "p1/n1"
    assert short_network("projects/p1/global/networks/n1") == "p1/n1"
    assert short_network("global/networks/default") == "default"


@pytest.mark.parametrize("obj", [
    {"name": "a"},
    {"name": "a", "allowed": [{"IPProtocol": "tcp"}], "denied": [{"IPProtocol": "tcp"}]},
    {"name": "a", "allowed": [{"IPProtocol": "tcp", "ports": ["70000"]}]},
    {"name": "a", "allowed": [{"IPProtocol": "tcp", "ports": ["ssh"]}]},
    {"name": "a", "allowed": [{"IPProtocol": "tcp"}], "sourceRanges": ["10.0.0.0/33"]},
    {"name": "a", "allowed": [{"IPProtocol": "tcp"}], "priority": 70000},
    {"name": "a", "allowed": [{"IPProtocol": "tcp"}], "direction": "SIDEWAYS"},
    {"allowed": [{"IPProtocol": "tcp"}]},
])
def test_invalid_rules(obj):
    with pytest.raises(RuleError):
        parse_rule(obj)


def test_load_list_items_and_single():
    assert len(load_rules('[{"name": "a", "allowed": [{"IPProtocol": "udp"}]}]')) == 1
    assert len(load_rules('{"items": [{"name": "a", "allowed": [{"IPProtocol": "udp"}]}]}')) == 1
    assert len(load_rules('{"name": "a", "allowed": [{"IPProtocol": "udp"}]}')) == 1
    with pytest.raises(RuleError):
        load_rules("name: a")
