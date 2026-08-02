package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ppiankov/dnsspectre/internal/analyzer"
)

// WO-16: WriteSARIF emits valid SARIF 2.1.0 with rules, levels, and locations.
func TestWriteSARIF(t *testing.T) {
	findings := []analyzer.Finding{
		{
			Type:     analyzer.SubdomainTakeoverRisk,
			Severity: analyzer.SeverityCritical,
			Domain:   "a.example.com",
			Target:   "dead.s3.amazonaws.com",
			Service:  "AWS S3",
			Detail:   "CNAME a.example.com points to dead.s3.amazonaws.com (AWS S3) which returns NXDOMAIN and is claimable",
		},
		{
			Type:     analyzer.NoCAARecord,
			Severity: analyzer.SeverityLow,
			Domain:   "a.example.com",
			Detail:   "domain a.example.com has no CAA record to restrict certificate issuance",
		},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, "example.com", findings); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var doc sarifReport
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\n%s", err, buf.String())
	}
	if doc.Schema != sarifSchema {
		t.Errorf("$schema: want %q, got %q", sarifSchema, doc.Schema)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version: want 2.1.0, got %q", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs: want 1, got %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "dnsspectre" {
		t.Errorf("driver name: want dnsspectre, got %q", run.Tool.Driver.Name)
	}
	if len(run.Results) != 2 {
		t.Fatalf("results: want 2, got %d", len(run.Results))
	}

	r0 := run.Results[0]
	if r0.RuleID != "SUBDOMAIN_TAKEOVER_RISK" {
		t.Errorf("ruleId: want SUBDOMAIN_TAKEOVER_RISK, got %q", r0.RuleID)
	}
	if r0.Level != "error" {
		t.Errorf("level: want error, got %q", r0.Level)
	}
	if r0.Message.Text == "" {
		t.Error("message text is empty")
	}
	if len(r0.LogicalLocations) != 1 || r0.LogicalLocations[0].Kind != "domain" || r0.LogicalLocations[0].Name != "a.example.com" {
		t.Errorf("logicalLocation: want kind=domain name=a.example.com, got %+v", r0.LogicalLocations)
	}

	if run.Results[1].Level != "note" {
		t.Errorf("level: want note for LOW, got %q", run.Results[1].Level)
	}

	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("rules: want 2 distinct, got %d", len(run.Tool.Driver.Rules))
	}
}

// WO-16: an empty findings slice still yields a valid SARIF envelope.
func TestWriteSARIF_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, "example.com", nil); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc sarifReport
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version: want 2.1.0, got %q", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs: want 1, got %d", len(doc.Runs))
	}
	if len(doc.Runs[0].Results) != 0 {
		t.Errorf("results: want 0, got %d", len(doc.Runs[0].Results))
	}
}
