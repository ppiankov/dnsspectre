# dnsspectre

[![CI](https://github.com/ppiankov/dnsspectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/dnsspectre/actions/workflows/ci.yml)
[![ANCC](https://img.shields.io/badge/ANCC-compliant-brightgreen)](https://ancc.dev)

**dnsspectre** — DNS hygiene and subdomain takeover detection. Part of [SpectreHub](https://spectrehub.dev).

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

### Windows

Download `dnsspectre_*_windows_amd64.zip` from [releases](https://github.com/ppiankov/dnsspectre/releases), unzip it, and run:

```powershell
.\dnsspectre.exe version
```

Or install with Go:

```powershell
go install github.com/ppiankov/dnsspectre/cmd/dnsspectre@latest
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

dnsspectre feeds DNS hygiene findings into [SpectreHub](https://spectrehub.dev) for unified visibility across your infrastructure.

```sh
spectrehub collect --tool dnsspectre
```

## Safety

dnsspectre operates in **read-only mode**. It inspects and reports — never modifies, deletes, or alters your DNS records.

## Documentation

| Document | Contents |
|----------|----------|
| [CLI Reference](docs/cli-reference.md) | Full command reference, flags, and configuration |

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Obsta Labs](https://obstalabs.dev)
