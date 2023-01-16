from gcp_firewall_audit.rules import parse_rule


def mk(name="r", **kw):
    obj = {"name": name, "network": "https://www.googleapis.com/compute/v1/projects/acme-prod-1234/global/networks/vpc"}
    if "allowed" not in kw and "denied" not in kw:
        kw["allowed"] = [{"IPProtocol": "tcp", "ports": ["22"]}]
    obj.update(kw)
    return parse_rule(obj)
