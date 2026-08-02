package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ppiankov/dnsspectre/internal/analyzer"
)

// WO-16: SARIF 2.1.0 schema/version constants for the report envelope.
const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
)

// WO-16: top-level SARIF report envelope ($schema, version, runs).
type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

// WO-16: a single run: the tool driver and its results.
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

// WO-16: tool wrapper around the driver descriptor.
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

// WO-16: tool driver: name, information URI, and declared rules.
type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

// WO-16: a rule entry, one per distinct finding type.
type sarifRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// WO-16: a SARIF result (ruleId, level, message, logicalLocations).
type sarifResult struct {
	RuleID           string                 `json:"ruleId"`
	Level            string                 `json:"level"`
	Message          sarifMessage           `json:"message"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

// WO-16: result message wrapper.
type sarifMessage struct {
	Text string `json:"text"`
}

// WO-16: the scanned domain modeled as a logical location (a domain is not a
// file artifact, so it is not a physical artifactLocation; SARIF §3.28).
type sarifLogicalLocation struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// WO-16: maps dnsspectre severity to a SARIF result.level
// (none | note | warning | error).
var severityToSarifLevel = map[analyzer.Severity]string{
	analyzer.SeverityCritical: "error",
	analyzer.SeverityHigh:     "error",
	analyzer.SeverityMedium:   "warning",
	analyzer.SeverityLow:      "note",
	analyzer.SeverityInfo:     "note",
}

// WO-16: WriteSARIF emits findings as a SARIF 2.1.0 log; each finding becomes
// a result keyed by finding type, levelled by severity, located at its domain.
func WriteSARIF(w io.Writer, zoneName string, findings []analyzer.Finding) error {
	rules := make([]sarifRule, 0, len(findings))
	seen := make(map[string]bool, len(findings))
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		ruleID := string(f.Type)
		// WO-16: declare one rule per distinct finding type.
		if !seen[ruleID] {
			seen[ruleID] = true
			rules = append(rules, sarifRule{
				ID:          ruleID,
				Name:        ruleID,
				Description: sarifRuleDescription(f.Type),
			})
		}

		// WO-16: level the result by severity (fallback warning).
		level := severityToSarifLevel[f.Severity]
		if level == "" {
			level = "warning"
		}

		// WO-16: locate the result at its domain (fall back to the zone name).
		name := f.Domain
		if name == "" {
			name = zoneName
		}

		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   level,
			Message: sarifMessage{Text: f.Detail},
			LogicalLocations: []sarifLogicalLocation{{
				Kind: "domain",
				Name: name,
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

// WO-16: human-readable rule description per finding type for tool.driver.rules.
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
