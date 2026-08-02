# Changelog

All notable changes to dnsspectre will be documented in this file.

## [Unreleased]

- Wire config-file keys (platform, domain, zone, format, timeout) with flag-over-config precedence
- Load custom takeover fingerprints from a file via `--fingerprints` / config
- Add SARIF output format (`--format sarif`)
- Deduplicate subdomain-takeover findings per CNAME target
- Expand CI build/test matrix to Windows and macOS

## [0.1.0] - 2026-03-02

- Initial scaffold
