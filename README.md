# gcp-firewall-audit

Audit Google Cloud VPC firewall rules: internet-exposed ports, overly broad rules, disabled and shadowed rules.

## Planned scope

Offline on `gcloud compute firewall-rules list --format=json`. Flag INGRESS allow from 0.0.0.0/0 (or ::/0) on sensitive ports (configurable), all protocols/ports, rules with no target tags or service accounts (apply to all instances), disabled rules, rules shadowed by a higher-priority (lower number) rule with same direction/network that fully covers them (deny shadowing allow and vice versa), and logging disabled on exposed rules. Be exact about GCP priority semantics (0-65535, lower wins) and implied rules. Table/JSON, exit codes.
