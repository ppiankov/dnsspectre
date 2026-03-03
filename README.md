# dnsspectre

[![CI](https://github.com/ppiankov/dnsspectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/dnsspectre/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ppiankov/dnsspectre)](https://goreportcard.com/report/github.com/ppiankov/dnsspectre)

**dnsspectre** — DNS hygiene and subdomain takeover detection. Part of [SpectreHub](https://github.com/ppiankov/spectrehub).

## What it is

- Scans DNS zones for dangling records pointing to deleted resources
- Detects subdomain takeover vectors (CNAME, NS, MX targets)
- Checks for missing CAA records
- Supports Route53, Cloud DNS, Azure DNS, and Cloudflare
- Outputs text, JSON, SARIF, and SpectreHub formats

## What it is NOT

- Not a DNS monitoring service — point-in-time scanner
- Not a penetration testing tool — detects risk, does not exploit
- Not a DNS manager — reports findings, never modifies records
- Not a certificate manager — flags missing CAA, does not issue certs

## Quick start

### Homebrew

```sh
brew tap ppiankov/tap
brew install dnsspectre
```

### From source

```sh
git clone https://github.com/ppiankov/dnsspectre.git
cd dnsspectre
make build
```

### Usage

```sh
dnsspectre scan --provider route53 --format json
```

## CLI commands

| Command | Description |
|---------|-------------|
| `dnsspectre scan` | Scan DNS zones for dangling records and takeover risk |
| `dnsspectre init` | Generate config file and provider credentials |
| `dnsspectre version` | Print version |

## SpectreHub integration

dnsspectre feeds DNS hygiene findings into [SpectreHub](https://github.com/ppiankov/spectrehub) for unified visibility across your infrastructure.

```sh
spectrehub collect --tool dnsspectre
```

## Safety

dnsspectre operates in **read-only mode**. It inspects and reports — never modifies, deletes, or alters your DNS records.

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Obsta Labs](https://github.com/ppiankov)
