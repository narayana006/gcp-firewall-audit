from helpers import mk

from gcp_firewall_audit.checks import audit, covers, takes_precedence

TCP = lambda *p: {"IPProtocol": "tcp", "ports": list(p)}  # noqa: E731


def codes(findings, rule=None):
    return sorted(f.code for f in findings if rule is None or f.rule == rule)


def test_internet_sensitive_port():
    f = audit([mk("ssh", sourceRanges=["0.0.0.0/0"], targetTags=["bastion"], logConfig={"enable": True})])
    assert [(x.code, x.severity) for x in f] == [("INTERNET_SENSITIVE_PORT", "high")]
    assert "22/ssh" in f[0].message


def test_ipv6_any_is_public_and_port_range_hits():
    f = audit([mk("r", allowed=[TCP("3000-3400")], sourceRanges=["::/0"], targetTags=["a"])])
    assert "INTERNET_SENSITIVE_PORT" in codes(f)
    assert "3306/mysql" in f[0].message and "3389/rdp" in f[0].message


def test_internet_all_ports_variants():
    for allowed in ([{"IPProtocol": "all"}], [{"IPProtocol": "tcp"}], [TCP("0-65535")],
                    [TCP("0-1000", "1001-65535")]):
        f = audit([mk("r", allowed=allowed, sourceRanges=["0.0.0.0/0"], targetTags=["x"])])
        assert ("INTERNET_ALL_PORTS", "critical") in [(x.code, x.severity) for x in f], allowed


def test_no_source_means_internet():
    f = audit([mk("r", allowed=[TCP("3389")], targetTags=["win"])])
    assert "INTERNET_SENSITIVE_PORT" in codes(f)


def test_non_sensitive_public_port_is_low_and_custom_ports():
    rule = mk("r", allowed=[TCP("443")], sourceRanges=["0.0.0.0/0"], targetTags=["web"], logConfig={"enable": True})
    assert [(x.code, x.severity) for x in audit([rule])] == [("INTERNET_EXPOSED", "low")]
    assert codes(audit([rule], sensitive={443: "https"})) == ["INTERNET_SENSITIVE_PORT"]


def test_icmp_only_never_hits_ports():
    f = audit([mk("r", allowed=[{"IPProtocol": "icmp"}], sourceRanges=["0.0.0.0/0"], targetTags=["x"],
                  logConfig={"enable": True})])
    assert codes(f) == ["INTERNET_EXPOSED"]


def test_no_targets_and_no_logging_on_exposed():
    f = audit([mk("r", allowed=[TCP("80")], sourceRanges=["0.0.0.0/0"])])
    sev = {x.code: x.severity for x in f}
    assert sev["NO_TARGETS"] == "medium" and sev["NO_LOGGING"] == "low"


def test_internal_broad_rule():
    f = audit([mk("r", allowed=[{"IPProtocol": "all"}], sourceRanges=["10.0.0.0/8"])])
    assert {(x.code, x.severity) for x in f} == {("ALL_PORTS", "medium"), ("NO_TARGETS", "low")}


def test_deny_and_egress_rules_not_exposure_findings():
    assert audit([mk("d", denied=[{"IPProtocol": "all"}], sourceRanges=["0.0.0.0/0"])]) == []
    assert audit([mk("e", direction="EGRESS", allowed=[TCP("22")], targetTags=["x"])]) == []


def test_disabled_rule_only_reported_as_disabled():
    f = audit([mk("r", allowed=[{"IPProtocol": "all"}], sourceRanges=["0.0.0.0/0"], disabled=True)])
    assert codes(f) == ["DISABLED"]


def test_precedence():
    a, b = mk("a", priority=100), mk("b", priority=200)
    assert takes_precedence(a, b) and not takes_precedence(b, a)
    d = mk("d", priority=200, denied=[TCP("22")])
    assert takes_precedence(d, b) and not takes_precedence(b, d)
    assert not takes_precedence(mk("x", priority=200), b)  # same priority, same action: indeterminate


def test_shadowed_allow_by_deny():
    deny = mk("deny-ssh", priority=100, denied=[TCP("22")], sourceRanges=["0.0.0.0/0"])
    allow = mk("allow-ssh", priority=1000, allowed=[TCP("22")], sourceRanges=["203.0.113.0/24"],
               targetTags=["bastion"])
    f = [x for x in audit([deny, allow]) if x.code == "SHADOWED"]
    assert len(f) == 1 and f[0].rule == "allow-ssh" and f[0].related_rule == "deny-ssh"
    assert "never allows anything" in f[0].message


def test_equal_priority_deny_shadows_allow():
    deny = mk("deny", priority=1000, denied=[TCP("22")], sourceRanges=["0.0.0.0/0"])
    allow = mk("allow", priority=1000, sourceRanges=["198.51.100.0/24"])
    assert "SHADOWED" in codes(audit([deny, allow]), "allow")


def test_partial_overlap_is_not_shadowing():
    a = mk("a", priority=100, allowed=[TCP("22")], sourceRanges=["10.0.0.0/16"])
    b = mk("b", priority=200, allowed=[TCP("22", "80")], sourceRanges=["10.0.0.0/16"])
    c = mk("c", priority=200, allowed=[TCP("22")], sourceRanges=["10.0.0.0/8"])
    d = mk("d", priority=200, allowed=[TCP("22")], sourceRanges=["10.0.0.0/16"], targetTags=["x"])
    assert not covers(a, b) and not covers(a, c)
    assert covers(a, d)  # a applies to all instances
    assert not covers(mk("t", targetTags=["x"], sourceRanges=["10.0.0.0/16"]), mk("u", sourceRanges=["10.0.0.0/16"]))


def test_port_ranges_merge_across_entries():
    a = mk("a", priority=1, allowed=[TCP("1-100"), TCP("101-200")], sourceRanges=["0.0.0.0/0"])
    b = mk("b", priority=2, allowed=[TCP("50-150")], sourceRanges=["192.0.2.0/24"])
    assert covers(a, b)
    assert not covers(a, mk("c", priority=2, allowed=[{"IPProtocol": "tcp"}], sourceRanges=["192.0.2.0/24"]))
    assert covers(mk("all", allowed=[{"IPProtocol": "all"}]), b)


def test_different_network_or_direction_never_covers():
    a = mk("a", priority=1, allowed=[{"IPProtocol": "all"}])
    other = mk("b", priority=2, network="projects/p/global/networks/other")
    assert not covers(a, other)
    assert not covers(a, mk("e", priority=2, direction="EGRESS"))


def test_source_tags_coverage():
    b = mk("b", priority=2, sourceTags=["web"])
    assert covers(mk("a", priority=1, sourceTags=["web", "api"]), b)
    assert not covers(mk("a", priority=1, sourceRanges=["0.0.0.0/0"]), b)
    assert covers(mk("a", priority=1, sourceRanges=["0.0.0.0/0", "::/0"]), b)
    assert not covers(mk("a", priority=1, sourceTags=["web"]), mk("c", sourceRanges=["10.0.0.0/8"]))


def test_redundant_and_disabled_rules_do_not_shadow():
    a = mk("a", priority=100, sourceRanges=["10.0.0.0/8"], targetTags=["x"])
    b = mk("b", priority=200, sourceRanges=["10.1.0.0/16"], targetTags=["x"])
    assert codes(audit([a, b]), "b") == ["REDUNDANT"]
    a_off = mk("a", priority=100, sourceRanges=["10.0.0.0/8"], targetTags=["x"], disabled=True)
    assert "REDUNDANT" not in codes(audit([a_off, b]))


def test_egress_shadowing_by_destination():
    a = mk("a", priority=100, direction="EGRESS", denied=[{"IPProtocol": "all"}], destinationRanges=["0.0.0.0/0"])
    b = mk("b", priority=200, direction="EGRESS", allowed=[TCP("443")], destinationRanges=["198.51.100.0/24"])
    assert "SHADOWED" in codes(audit([a, b]), "b")
    v6 = mk("c", priority=200, direction="EGRESS", allowed=[TCP("443")], destinationRanges=["2001:db8::/32"])
    assert not covers(a, v6)


def test_ignore_codes():
    f = audit([mk("r", allowed=[TCP("80")], sourceRanges=["0.0.0.0/0"])], ignore=["no_logging", "NO_TARGETS"])
    assert codes(f) == ["INTERNET_EXPOSED"]
