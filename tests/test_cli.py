import io
import json
import pathlib

import pytest

from gcp_firewall_audit.cli import main

EX = pathlib.Path(__file__).resolve().parent.parent / "examples"


def test_example_table(capsys):
    rc = main([str(EX / "firewall-rules.json")])
    out = capsys.readouterr().out
    assert rc == 1
    assert "Audited 14 firewall rule(s) (1 disabled) in 2 network(s)" in out
    assert "deny-db-from-internet" in out and "SHADOWED" in out
    assert "REDUNDANT" in out and "allow-ssh-iap-old" in out
    assert "implied rules at priority 65535" in out


def test_example_json(capsys):
    main([str(EX / "firewall-rules.json"), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["findings"]["high"] == 4
    assert data["summary"]["networks"] == ["acme-prod-1234/default", "acme-prod-1234/prod-vpc"]


def test_clean_example_passes(capsys):
    assert main([str(EX / "clean-rules.json")]) == 0
    assert main([str(EX / "clean-rules.json"), "--fail-on", "low"]) == 1  # public HTTPS is reported as low


def test_network_filter_and_show_rules(capsys):
    rc = main([str(EX / "firewall-rules.json"), "--network", "default", "--show-rules", "--fail-on", "never"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "prod-vpc" not in out
    assert "(all instances)" in out


def test_sensitive_port_options(capsys):
    main([str(EX / "clean-rules.json"), "--add-sensitive-ports", "443/https", "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert any(f["code"] == "INTERNET_SENSITIVE_PORT" for f in data["findings"])
    main([str(EX / "firewall-rules.json"), "--sensitive-ports", "3389", "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    hits = [f["rule"] for f in data["findings"] if f["code"] == "INTERNET_SENSITIVE_PORT"]
    assert hits == ["default-allow-rdp"]
    with pytest.raises(SystemExit):
        main(["--sensitive-ports", "ssh"])


def test_stdin_and_errors(capsys, monkeypatch, tmp_path):
    monkeypatch.setattr("sys.stdin", io.StringIO("[]"))
    assert main([]) == 0
    assert main([str(tmp_path / "nope.json")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text('[{"name": "x"}]')
    assert main([str(bad)]) == 2
