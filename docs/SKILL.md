# dnsspectre

DNS configuration and takeover vulnerability scanner.

## Install

```
brew install ppiankov/tap/dnsspectre
```

Or via Go:

```
go install github.com/ppiankov/dnsspectre/cmd/dnsspectre@latest
```

## Commands

### dnsspectre scan

Scans DNS zones for security findings.

**Flags:**
- `--config path` — config file path (default: $DNSSPECTRE_CONFIG or platform-specific dir)
- `--format text` — human-readable text output (default)
- `--format json` — spectre/v1 JSON envelope
- `--format sarif` — SARIF 2.1.0 for CI integration
- `--format spectrehub` — SpectreHub aggregator format
- `--baseline path` — suppress known findings

**JSON output:**
```json
{
  "version": "spectre/v1",
  "scanner": "dnsspectre",
  "target": "DNS zones",
  "findings": [
    {
      "id": "FIND-001",
      "severity": "high",
      "title": "finding description",
      "resource": "resource identifier",
      "detail": "detailed explanation"
    }
  ],
  "summary": {
    "total": 1,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0
  }
}
```

**Exit codes:**
- 0: scan complete, no findings
- 1: scan complete, findings detected
- 2: scan failed (connectivity, auth, config error)

### dnsspectre init

Generate a sample configuration file.

**Flags:**
- `--path path` — override config file location (default: platform-specific config dir)

**Exit codes:**
- 0: config created
- 1: config already exists or error

## Handoffs

- Output: spectre/v1 JSON envelope. Next: spectrehub for aggregation across scanners.
- Output: SARIF. Next: CI security gates.
- Refused questions: how to fix findings, whether to remediate, risk acceptance decisions.

## What this does NOT do

- Does not remediate or modify DNS zones — scan is read-only
- Does not store findings or manage a findings database
- Does not replace dedicated DNS zones monitoring — point-in-time security audit only

## Failure Modes

- Authentication failure: returns exit code 2. Distrust: all findings fields. Safe fallback: report scan failure, do not cache.
- Network timeout: returns exit code 2. Distrust: completeness of findings. Safe fallback: partial results with warning.
- Rate limiting: returns partial findings with truncation warning. Distrust: summary counts.

## Parsing examples

```bash
dnsspectre scan --format json | jq '.summary'
dnsspectre scan --format json | jq '.findings[] | select(.severity == "critical")'
```

---

This tool follows the [Agent-Native CLI Convention](https://ancc.dev). Validate with: `ancc validate .`
