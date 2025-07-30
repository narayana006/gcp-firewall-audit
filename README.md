# gcp-firewall-audit

Audit Google Cloud VPC firewall rules offline: internet-exposed ports, overly broad rules, disabled rules and rules shadowed by a higher-priority rule.

**Status:** v0.1. Works today on `gcloud compute firewall-rules list --format=json` output: nine checks including exact priority/shadowing analysis, table and JSON output, CI exit codes. It never calls Google Cloud.

## Install

```bash
pip install git+https://github.com/narayana006/gcp-firewall-audit
```

Python 3.10+; no runtime dependencies.

## Quick start

```bash
gcloud compute firewall-rules list --project acme-prod-1234 --format=json > rules.json
gcp-firewall-audit rules.json
```

On the bundled example (`examples/firewall-rules.json`, hand-written and illustrative: the four pre-populated `default` network rules plus a `prod-vpc` with a few common mistakes):

```text
$ gcp-firewall-audit examples/firewall-rules.json
Audited 14 firewall rule(s) (1 disabled) in 2 network(s) from examples/firewall-rules.json

SEVERITY  CODE                     RULE                    NETWORK                  DETAIL
--------  -----------------------  ----------------------  -----------------------  ----------------------------------------------------------------------------------------------------------------------------------------------------
high      INTERNET_SENSITIVE_PORT  default-allow-rdp       acme-prod-1234/default   allows 3389/rdp from 0.0.0.0/0
high      INTERNET_SENSITIVE_PORT  default-allow-ssh       acme-prod-1234/default   allows 22/ssh from 0.0.0.0/0
high      INTERNET_SENSITIVE_PORT  allow-db-debug          acme-prod-1234/prod-vpc  allows 5432/postgres from 0.0.0.0/0, ::/0
high      INTERNET_SENSITIVE_PORT  allow-legacy-app        acme-prod-1234/prod-vpc  allows 9200/elasticsearch from 0.0.0.0/0
medium    NO_TARGETS               default-allow-icmp      acme-prod-1234/default   internet-exposed rule has no target tags or service accounts, so it applies to every instance in the network
medium    ALL_PORTS                default-allow-internal  acme-prod-1234/default   allows tcp:0-65535 udp:0-65535 (every port) from 10.128.0.0/9
medium    NO_TARGETS               default-allow-rdp       acme-prod-1234/default   internet-exposed rule has no target tags or service accounts, so it applies to every instance in the network
medium    NO_TARGETS               default-allow-ssh       acme-prod-1234/default   internet-exposed rule has no target tags or service accounts, so it applies to every instance in the network
medium    ALL_PORTS                allow-internal-all      acme-prod-1234/prod-vpc  allows all (every port) from 10.10.0.0/16
medium    SHADOWED                 deny-db-from-internet   acme-prod-1234/prod-vpc  allow rule allow-db-debug (priority 900) covers all of its traffic, so this deny rule (priority 1000) never blocks anything; that traffic is allowed
low       INTERNET_EXPOSED         default-allow-icmp      acme-prod-1234/default   allows icmp from 0.0.0.0/0
low       NO_LOGGING               default-allow-icmp      acme-prod-1234/default   firewall rules logging is off for an internet-exposed rule
low       NO_TARGETS               default-allow-internal  acme-prod-1234/default   no target tags or service accounts; applies to every instance in the network
low       NO_LOGGING               default-allow-rdp       acme-prod-1234/default   firewall rules logging is off for an internet-exposed rule
low       NO_LOGGING               default-allow-ssh       acme-prod-1234/default   firewall rules logging is off for an internet-exposed rule
low       DISABLED                 allow-all-temp          acme-prod-1234/prod-vpc  rule is disabled (not enforced); allow all
low       NO_LOGGING               allow-db-debug          acme-prod-1234/prod-vpc  firewall rules logging is off for an internet-exposed rule
low       INTERNET_EXPOSED         allow-https-lb          acme-prod-1234/prod-vpc  allows tcp:80,tcp:443 from 0.0.0.0/0
low       NO_TARGETS               allow-internal-all      acme-prod-1234/prod-vpc  no target tags or service accounts; applies to every instance in the network
low       NO_LOGGING               allow-legacy-app        acme-prod-1234/prod-vpc  firewall rules logging is off for an internet-exposed rule
low       REDUNDANT                allow-ssh-iap-old       acme-prod-1234/prod-vpc  fully covered by allow-ssh-iap (priority 1000, also allow); allow-ssh-iap-old (priority 2000) never decides any traffic

Findings: 0 critical, 4 high, 6 medium, 11 low
Note: every VPC network also has implied rules at priority 65535 (allow all egress, deny all ingress) that are not in this export, and hierarchical / network firewall policies are not included.
$ echo $?
1
```

Add `--show-rules` to print the normalised rule list (network, direction, priority, action, protocols, sources, targets, enabled, logging) above the findings.

## How rules are interpreted

The tool follows the documented VPC firewall rule semantics:

- **Priority** is 0-65535, default 1000; the lowest number that matches wins. At equal priority a deny overrides an allow. Two rules with the same priority and action are left alone (Google documents the choice between them as indeterminate).
- **Direction** defaults to `INGRESS`. Rules only interact with rules in the same network and direction.
- **Targets:** a rule with neither `targetTags` nor `targetServiceAccounts` applies to every instance in the network.
- **Sources:** an ingress rule with no `sourceRanges`, `sourceTags` or `sourceServiceAccounts` uses `0.0.0.0/0` (IPv4 only). `sourceRanges` and `sourceTags` are combined with OR. An egress rule with no `destinationRanges` is treated as `0.0.0.0/0`.
- **Protocols:** `allowed[]` / `denied[]` entries are `{IPProtocol, ports}`. A protocol with no `ports` matches every port; `IPProtocol: "all"` matches every protocol. Well-known protocol numbers (6, 17, 1, 132, 50, 51, 4) are mapped to names. `tcp:0-65535` counts as all ports.
- **Disabled** rules (`disabled: true`) are not enforced: they are reported once and ignored by every other check.
- **Logging** is on only when `logConfig.enable` is `true`.

## Checks

| Code | Severity | Flags |
| --- | --- | --- |
| `INTERNET_ALL_PORTS` | critical | enabled ingress allow from `0.0.0.0/0` or `::/0` on all protocols, or all TCP/UDP/SCTP ports |
| `INTERNET_SENSITIVE_PORT` | high | the same, for a sensitive port (default list below) |
| `INTERNET_EXPOSED` | low | any other internet-facing allow (for inventory, e.g. 80/443) |
| `NO_TARGETS` | medium if internet-exposed, else low | allow rule with no target tags or service accounts |
| `NO_LOGGING` | low | internet-exposed rule with firewall rules logging off |
| `ALL_PORTS` | medium | non-internet ingress allow on all protocols or all ports |
| `SHADOWED` | medium | a higher-precedence rule with the **opposite** action fully covers this rule, so it never takes effect (an allow that never allows, or a deny that never blocks) |
| `REDUNDANT` | low | a higher-precedence rule with the **same** action fully covers this rule |
| `DISABLED` | low | rule is disabled |

"Fully covers" means: same network and direction; the covering rule's targets include the other's (no targets covers everything; otherwise tag or service-account subsets); every source range fits inside one of its source ranges (sources given as tags or service accounts are only covered by the same tags/accounts, or by a rule allowing both `0.0.0.0/0` and `::/0`); destination ranges likewise; and every protocol and port is included (port ranges are merged across entries).

Default sensitive ports: 20, 21 (ftp), 22 (ssh), 23 (telnet), 445 (smb), 1433 (mssql), 1521 (oracle), 2375, 2376 (docker), 2379 (etcd), 3306 (mysql), 3389 (rdp), 5432 (postgres), 5601 (kibana), 5900 (vnc), 6379 (redis), 9200 (elasticsearch), 10250 (kubelet), 11211 (memcached), 27017 (mongodb).

## Usage

```text
gcp-firewall-audit [FILE ...] [--format table|json] [--show-rules]
                   [--sensitive-ports 22/ssh,3389/rdp | --add-sensitive-ports 8443/admin]
                   [--network NAME] [--ignore CODE] [--fail-on low|medium|high|critical|never]
```

- Input: a JSON list of rules (gcloud output), a REST `firewalls.list` response (`{"items": [...]}`), or a single rule object. Several files can be combined; `-` or no file reads stdin.
- `--network`: keep only rules in this network, given as `name` or `project/name` (repeatable).
- `--ignore`: drop a finding code (repeatable), e.g. `--ignore INTERNET_EXPOSED`.

Exit codes: `0` no finding at or above `--fail-on` (default `high`), `1` at least one, `2` invalid input (not JSON, rule without `allowed`/`denied`, bad CIDR, port or priority).

## Required permissions

The tool needs none. Exporting the rules needs `compute.firewalls.list` on the project (included in, for example, `roles/compute.viewer` and `roles/compute.securityAdmin`).

## Features

- [x] Internet exposure on sensitive ports (configurable) and on all ports/protocols, IPv4 and IPv6
- [x] Rules that apply to every instance (no target tags or service accounts)
- [x] Disabled rules, and logging off on exposed rules
- [x] Shadowed and redundant rules using exact priority and deny-over-allow semantics
- [x] Table, normalised rule list and JSON output; CI exit codes
- [ ] Shadowing by a combination of several rules (today one rule must cover the other on its own)
- [ ] Hierarchical and global/regional network firewall policies
- [ ] Cross-check against instance tags and service accounts (rules whose targets match no VM)

## Limitations

- Only VPC firewall rules are analysed. Hierarchical firewall policies and network firewall policies are evaluated by Google Cloud before or alongside VPC rules and can change the outcome; they are not read.
- The implied rules (allow all egress, deny all ingress, priority 65535) are not in the gcloud export and are not reported, but they are why a missing allow means "blocked".
- Shadowing is pairwise: a rule covered only by the union of two or more rules is not reported. This avoids false positives at the cost of some misses.
- A source like `0.0.0.0/1` is not treated as "the internet"; only `/0` ranges are.
- Port numbers for protocols other than TCP, UDP and SCTP are ignored when matching sensitive ports.
- The examples are hand-written and illustrative (fictional project `acme-prod-1234`); the health-check and IAP ranges in them are Google's published ranges.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Contributing

Issues and pull requests are welcome. For a wrong result, please attach the two or three rules involved (with fictional names and ranges) and say what you expected.

Built and maintained by [Narayana Vemburaj](https://github.com/narayana006).

## License

[MIT](LICENSE)
