# Changelog

All notable changes to dnsspectre will be documented in this file.

## [Unreleased]

## [0.2.0] - 2026-08-02

- Wire config-file keys (platform, domain, zone, format, timeout) with flag-over-config precedence
- Load custom takeover fingerprints from a file via `--fingerprints` / config
- Add SARIF output format (`--format sarif`)
- Deduplicate subdomain-takeover findings per CNAME target
- Expand CI build/test matrix to Windows and macOS
- Bump Go toolchain to 1.25 (ci.yml + release.yml)
- Fix Windows golden-test line endings via .gitattributes (LF normalization)

## [0.1.0] - 2026-03-02

- Initial scaffold
