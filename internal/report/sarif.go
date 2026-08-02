package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ppiankov/dnsspectre/internal/analyzer"
)

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
)

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// severityToSarifLevel maps dnsspectre severity to a SARIF result.level.
// SARIF 2.1.0 permits only: none | note | warning | error.
var severityToSarifLevel = map[analyzer.Severity]string{
	analyzer.SeverityCritical: "error",
	analyzer.SeverityHigh:     "error",
	analyzer.SeverityMedium:   "warning",
	analyzer.SeverityLow:      "note",
	analyzer.SeverityInfo:     "note",
}

// WriteSARIF writes findings as a SARIF 2.1.0 log. Each finding becomes a
// result keyed by its finding type (ruleId), levelled by severity, and located
// at its domain. Empty findings yield a valid run with no results.
func WriteSARIF(w io.Writer, zoneName string, findings []analyzer.Finding) error {
	rules := make([]sarifRule, 0, len(findings))
	seen := make(map[string]bool, len(findings))
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		ruleID := string(f.Type)
		if !seen[ruleID] {
			seen[ruleID] = true
			rules = append(rules, sarifRule{
				ID:          ruleID,
				Name:        ruleID,
				Description: sarifRuleDescription(f.Type),
			})
		}

		level := severityToSarifLevel[f.Severity]
		if level == "" {
			level = "warning"
		}

		uri := f.Domain
		if uri == "" {
			uri = zoneName
		}

		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   level,
			Message: sarifMessage{Text: f.Detail},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: uri},
				},
			}},
		})
	}

	doc := sarifReport{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "dnsspectre",
					InformationURI: "https://github.com/ppiankov/dnsspectre",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sarif: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write sarif: %w", err)
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return fmt.Errorf("write sarif newline: %w", err)
	}
	return nil
}

func sarifRuleDescription(t analyzer.FindingType) string {
	switch t {
	case analyzer.SubdomainTakeoverRisk:
		return "DNS record points to a claimable or deleted resource, enabling subdomain takeover"
	case analyzer.DanglingCNAME:
		return "CNAME points to a target that no longer resolves"
	case analyzer.DanglingMX:
		return "MX record points to a mail host that no longer resolves"
	case analyzer.DanglingNS:
		return "NS record delegates to a nameserver that no longer resolves"
	case analyzer.NoCAARecord:
		return "Domain has no CAA record restricting certificate issuance"
	default:
		return string(t)
	}
}
