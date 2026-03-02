# DNSSpectre

[![ANCC](https://img.shields.io/badge/ANCC-compliant-brightgreen)](https://ancc.dev)
[![CI](https://github.com/ppiankov/dnsspectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/dnsspectre/actions/workflows/ci.yml)
[![Go 1.24+](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

DNS hygiene and subdomain takeover detection. Finds dangling records, missing CAA, and claimable CNAME targets across Route53, Cloud DNS, Azure DNS, and Cloudflare.

Part of the [Spectre family](https://spectrehub.dev) of infrastructure cleanup tools.

## What it is

DNSSpectre scans your DNS zones for records that point to resources that no longer exist. A CNAME to a deleted S3 bucket, an MX record to a decommissioned mail server, an NS delegation to a nameserver you no longer control — these are subdomain takeover vectors. DNSSpectre resolves each record, matches against known service fingerprints, and reports findings with severity so you can prioritize remediation.

## What it is NOT

- Not a DNS monitoring service. DNSSpectre is a point-in-time scanner, not a daemon.
- Not a penetration testing tool. It detects takeover risk but does not exploit it.
- Not a DNS manager. It reports findings and lets you decide what to do.
- Not a certificate manager. It flags missing CAA records but does not issue or revoke certificates.
- Not a zone transfer tool. It uses cloud provider APIs or direct DNS queries, not AXFR.

## Philosophy

*Principiis obsta* — resist the beginnings.

Dangling DNS records are the easiest subdomain takeover vector and the hardest to notice. A CNAME that worked yesterday can become claimable today when someone deletes a cloud resource without updating DNS. DNSSpectre surfaces these conditions early — in scheduled audits, in CI, in security reviews — so they can be fixed before an attacker claims them.

The tool presents evidence and lets humans decide. It does not modify records, does not claim resources, and does not guess intent.

## Installation

```bash
# Homebrew
brew install ppiankov/tap/dnsspectre

# From source
git clone https://github.com/ppiankov/dnsspectre.git
cd dnsspectre && make build
```

## Quick start

```bash
# Scan a domain via direct DNS queries
dnsspectre scan --domain example.com

# Scan all Route53 zones
dnsspectre scan --platform aws

# Scan a specific Route53 zone
dnsspectre scan --platform aws --zone Z0123456789ABCDEF

# Scan GCP Cloud DNS
dnsspectre scan --platform gcp

# Scan Azure DNS
dnsspectre scan --platform azure

# Scan Cloudflare
dnsspectre scan --platform cloudflare

# JSON output for automation
dnsspectre scan --platform aws --format json

# Generate sample config
dnsspectre init
```

Requires valid cloud credentials for platform mode, or just a working DNS resolver for domain mode.

## What it detects

| Finding | Severity | Signal |
|---------|----------|--------|
| `SUBDOMAIN_TAKEOVER_RISK` | critical | CNAME matches a claimable service fingerprint (S3, GitHub Pages, Heroku, etc.) and target returns NXDOMAIN |
| `DANGLING_CNAME` | high | CNAME points to a non-existent domain (NXDOMAIN) |
| `DANGLING_NS` | high | NS record delegates to a non-existent nameserver |
| `DANGLING_MX` | medium | MX record points to a non-existent mail server |
| `NO_CAA_RECORD` | low | Domain has no CAA record to restrict certificate issuance |

## Service fingerprints

DNSSpectre includes a built-in fingerprint database for subdomain takeover detection. When a CNAME target returns NXDOMAIN and matches a known service pattern, the finding is escalated from `DANGLING_CNAME` to `SUBDOMAIN_TAKEOVER_RISK` (critical).

Supported services: AWS S3, GitHub Pages, Heroku, Azure Blob Storage, Azure Websites, Azure CDN, Azure Traffic Manager, Shopify, Fastly, Pantheon, Surge.sh, Unbounce, WordPress.com, Tumblr, Ghost, Fly.io, Netlify.

Custom fingerprints can be loaded with `--fingerprints /path/to/fingerprints.yaml`.

## Usage

```bash
dnsspectre scan [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--domain` | | Domain for direct DNS query mode |
| `--platform` | | Cloud platform: `aws`, `gcp`, `azure`, `cloudflare` |
| `--zone` | | Zone ID for platform mode (omit to scan all zones) |
| `--format` | `text` | Output format: `text`, `json`, `spectrehub` |
| `--timeout` | `5s` | DNS resolution timeout |
| `--fingerprints` | | Path to custom fingerprints file |

`--domain` and `--platform` are mutually exclusive.

**Other commands:**

| Command | Description |
|---------|-------------|
| `dnsspectre init` | Generate `.dnsspectre.yaml` config file |
| `dnsspectre version` | Print version, commit, and build date |

## Configuration

DNSSpectre reads `.dnsspectre.yaml` from the current directory:

```yaml
platform: aws
zone: Z0123456789ABCDEF
format: text
timeout: 5s
fingerprints: /path/to/custom-fingerprints.yaml
gcp:
  project: my-gcp-project
azure:
  subscription_id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
cloudflare:
  api_token: your-api-token
```

Generate a sample config with `dnsspectre init`.

## Authentication

| Provider | Method | Details |
|----------|--------|---------|
| AWS Route53 | Default credential chain | IAM role, `~/.aws/credentials`, `AWS_*` env vars |
| GCP Cloud DNS | Application Default Credentials | `gcloud auth`, `GOOGLE_APPLICATION_CREDENTIALS` |
| Azure DNS | DefaultAzureCredential | `az login`, env vars, managed identity |
| Cloudflare | API token | `DNSSPECTRE_CLOUDFLARE_API_TOKEN` or config file |
| Direct DNS | None | Uses system resolver |

## Output formats

**Text** (default): Human-readable table with severity, finding type, domain, target, and detail.

**JSON** (`--format json`): `spectre/v1` envelope with findings and summary:
```json
{
  "schema": "spectre/v1",
  "tool": "dnsspectre",
  "target": { "type": "dns-zone", "name": "example.com" },
  "findings": [...],
  "summary": {
    "total": 5,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1
  }
}
```

**SpectreHub** (`--format spectrehub`): `spectre/v1` envelope for SpectreHub ingestion.

## Architecture

```
dnsspectre/
├── cmd/dnsspectre/main.go          # Entry point (LDFLAGS version injection)
├── internal/
│   ├── commands/                   # Cobra CLI: scan, init, version
│   ├── analyzer/                   # Record analysis engine (CNAME, MX, NS, CAA checks)
│   ├── dns/                        # DNS resolver (miekg/dns), HTTP checker, fingerprint DB
│   ├── aws/                        # Route53 zone/record enumeration
│   ├── gcp/                        # Cloud DNS zone/record enumeration
│   ├── azure/                      # Azure DNS zone/record enumeration
│   ├── cloudflare/                 # Cloudflare zone/record enumeration
│   ├── config/                     # YAML config loader
│   ├── report/                     # Text, JSON, SpectreHub reporters
│   └── logging/                    # Structured logging
├── Makefile
└── go.mod
```

Key design decisions:

- Two scan modes: **platform mode** (enumerate zones via cloud API) and **DNS query mode** (direct resolution).
- Each provider implements `ListZones()` and `ListRecords()` behind a common interface.
- Analysis is provider-agnostic — the analyzer works on DNS records regardless of source.
- Fingerprint matching is deterministic: exact CNAME substring match + NXDOMAIN confirmation.
- No write operations. DNSSpectre never modifies DNS records.

## Project status

**Status: Beta** · **v0.1.0** · Pre-1.0

| Milestone | Status |
|-----------|--------|
| 4 cloud providers (Route53, Cloud DNS, Azure DNS, Cloudflare) | Complete |
| Direct DNS query mode | Complete |
| 5 finding types (takeover, dangling CNAME/NS/MX, missing CAA) | Complete |
| 17 service fingerprints for takeover detection | Complete |
| 3 output formats (text, JSON, SpectreHub) | Complete |
| Config file + init command | Complete |
| CI pipeline (test/lint/build) | Complete |
| Homebrew distribution | Complete |
| Test coverage >85% | Complete |
| SARIF output | Planned |
| v1.0 release | Planned |

Pre-1.0: CLI flags and config schemas may change between minor versions. JSON output structure (`spectre/v1`) is stable.

## Known limitations

- **DNS query mode is limited.** Without platform API access, DNSSpectre can only check records it knows about. Platform mode enumerates all records in a zone.
- **Fingerprint coverage.** The built-in fingerprint database covers 17 services. New services require fingerprint updates.
- **No recursive subdomain enumeration.** DNSSpectre checks records in known zones, not brute-force subdomain discovery.
- **CAA inheritance.** CAA records are inherited from parent domains. DNSSpectre checks per-domain only and may flag false positives if CAA is set on the parent.
- **Rate limits.** Cloud provider APIs may rate-limit large zone enumerations. Use `--zone` to scope scans.
- **TTL caching.** DNS resolvers cache responses. Very recently deleted resources may still resolve due to TTL.

## License

MIT License — see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and pull requests welcome.

Part of the [Spectre family](https://spectrehub.dev).
