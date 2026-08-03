package analyzer

import (
	"context"
	"fmt"
	"strings"

	"github.com/ppiankov/dnsspectre/internal/dns"
)

// Analyzer inspects DNS records and produces findings.
type Analyzer struct {
	resolver     dns.Resolver
	fingerprints []dns.Fingerprint
	checker      *dns.Checker
}

// New creates an Analyzer with the given resolver, fingerprint database, and
// optional HTTP checker for non-NXDomain fingerprint verification. Pass nil
// for checker to skip HTTP-based takeover detection.
func New(resolver dns.Resolver, fingerprints []dns.Fingerprint, checker *dns.Checker) *Analyzer {
	return &Analyzer{
		resolver:     resolver,
		fingerprints: fingerprints,
		checker:      checker,
	}
}

// Analyze inspects records and returns findings.
// Resolver errors (network failures) cause the affected record to be skipped.
func (a *Analyzer) Analyze(ctx context.Context, records []Record) ([]Finding, error) {
	var findings []Finding

	for _, rec := range records {
		switch rec.Type {
		case "CNAME":
			findings = append(findings, a.checkCNAME(ctx, rec)...)
		case "MX":
			findings = append(findings, a.checkMX(ctx, rec)...)
		case "NS":
			findings = append(findings, a.checkNS(ctx, rec)...)
		}
	}

	findings = append(findings, a.checkMissingCAA(ctx, records)...)

	return findings, nil
}

func (a *Analyzer) checkCNAME(ctx context.Context, rec Record) []Finding {
	var findings []Finding
	for _, target := range rec.Values {
		if target == "" {
			continue
		}
		result, err := a.resolver.ResolveA(ctx, target)
		if err != nil {
			continue
		}

		matched := dns.MatchCNAME(target, a.fingerprints)
		hasTakeover := false

		// WO-20: NXDOMAIN check — one takeover per CNAME target
		if result.Rcode == 3 {
			for _, fp := range matched {
				if fp.NXDomain {
					hasTakeover = true
					findings = append(findings, Finding{
						Type:     SubdomainTakeoverRisk,
						Severity: SeverityCritical,
						Domain:   rec.Name,
						Record:   rec,
						Target:   target,
						Service:  fp.Service,
						Detail:   fmt.Sprintf("CNAME %s points to %s (%s) which returns NXDOMAIN and is claimable", rec.Name, target, fp.Service),
					})
					break
				}
			}
		}

		// WO-33: HTTP-based check for non-NXDomain fingerprints
		if !hasTakeover && a.checker != nil {
			for _, fp := range matched {
				if !fp.NXDomain {
					url := fmt.Sprintf("https://%s", target)
					checkResult, checkErr := a.checker.Check(ctx, url, []dns.Fingerprint{fp})
					if checkErr != nil {
						continue
					}
					if checkResult != nil && checkResult.Matched {
						hasTakeover = true
						findings = append(findings, Finding{
							Type:     SubdomainTakeoverRisk,
							Severity: SeverityCritical,
							Domain:   rec.Name,
							Record:   rec,
							Target:   target,
							Service:  fp.Service,
							Detail:   fmt.Sprintf("CNAME %s points to %s (%s) which returns HTTP %d and is claimable", rec.Name, target, fp.Service, checkResult.StatusCode),
						})
						break
					}
				}
			}
		}

		if !hasTakeover && result.Rcode == 3 {
			findings = append(findings, Finding{
				Type:     DanglingCNAME,
				Severity: SeverityHigh,
				Domain:   rec.Name,
				Record:   rec,
				Target:   target,
				Detail:   fmt.Sprintf("CNAME %s points to %s which returns NXDOMAIN", rec.Name, target),
			})
		}
	}
	return findings
}

func (a *Analyzer) checkMX(ctx context.Context, rec Record) []Finding {
	var findings []Finding
	for _, val := range rec.Values {
		host := parseMXHost(val)
		if host == "" {
			continue
		}
		result, err := a.resolver.ResolveA(ctx, host)
		if err != nil {
			continue
		}
		if result.Rcode == 3 {
			findings = append(findings, Finding{
				Type:     DanglingMX,
				Severity: SeverityMedium,
				Domain:   rec.Name,
				Record:   rec,
				Target:   host,
				Detail:   fmt.Sprintf("MX record for %s points to %s which returns NXDOMAIN", rec.Name, host),
			})
		}
	}
	return findings
}

func (a *Analyzer) checkNS(ctx context.Context, rec Record) []Finding {
	var findings []Finding
	for _, ns := range rec.Values {
		ns = strings.TrimSpace(ns)
		ns = strings.TrimSuffix(ns, ".")
		if ns == "" {
			continue
		}
		result, err := a.resolver.ResolveA(ctx, ns)
		if err != nil {
			continue
		}
		if result.Rcode == 3 {
			findings = append(findings, Finding{
				Type:     DanglingNS,
				Severity: SeverityHigh,
				Domain:   rec.Name,
				Record:   rec,
				Target:   ns,
				Detail:   fmt.Sprintf("NS record for %s delegates to %s which returns NXDOMAIN", rec.Name, ns),
			})
		}
	}
	return findings
}

func (a *Analyzer) checkMissingCAA(ctx context.Context, records []Record) []Finding {
	domains := make(map[string]bool)
	hasCAA := make(map[string]bool)

	for _, rec := range records {
		domains[rec.Name] = true
		if rec.Type == "CAA" {
			hasCAA[rec.Name] = true
		}
	}

	var findings []Finding
	for domain := range domains {
		if hasCAA[domain] {
			continue
		}
		result, err := a.resolver.ResolveCAA(ctx, domain)
		if err != nil {
			continue
		}
		if len(result.CAAs) == 0 {
			findings = append(findings, Finding{
				Type:     NoCAARecord,
				Severity: SeverityLow,
				Domain:   domain,
				Record:   Record{Name: domain, Type: "CAA"},
				Detail:   fmt.Sprintf("domain %s has no CAA record to restrict certificate issuance", domain),
			})
		}
	}
	return findings
}

// parseMXHost extracts the hostname from an MX value like "10 mail.example.com".
func parseMXHost(val string) string {
	val = strings.TrimSpace(val)
	parts := strings.Fields(val)
	switch len(parts) {
	case 2:
		return strings.TrimSuffix(parts[1], ".")
	case 1:
		return strings.TrimSuffix(parts[0], ".")
	default:
		return ""
	}
}
