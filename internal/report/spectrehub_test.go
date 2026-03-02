package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ppiankov/dnsspectre/internal/analyzer"
)

func testFindings() []analyzer.Finding {
	return []analyzer.Finding{
		{
			Type:     analyzer.SubdomainTakeoverRisk,
			Severity: analyzer.SeverityCritical,
			Domain:   "cdn.example.com",
			Record:   analyzer.Record{Name: "cdn.example.com", Type: "CNAME", Values: []string{"old.s3.amazonaws.com"}, TTL: 300},
			Target:   "old.s3.amazonaws.com",
			Service:  "AWS S3",
			Detail:   "CNAME cdn.example.com points to old.s3.amazonaws.com (AWS S3) which returns NXDOMAIN and is claimable",
		},
		{
			Type:     analyzer.DanglingCNAME,
			Severity: analyzer.SeverityHigh,
			Domain:   "app.example.com",
			Record:   analyzer.Record{Name: "app.example.com", Type: "CNAME", Values: []string{"old.nxdomain.test"}, TTL: 600},
			Target:   "old.nxdomain.test",
			Detail:   "CNAME app.example.com points to old.nxdomain.test which returns NXDOMAIN",
		},
		{
			Type:     analyzer.NoCAARecord,
			Severity: analyzer.SeverityLow,
			Domain:   "example.com",
			Record:   analyzer.Record{Name: "example.com", Type: "CAA"},
			Detail:   "domain example.com has no CAA record",
		},
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSON(&buf, "example.com", testFindings())
	if err != nil {
		t.Fatal(err)
	}

	golden, err := os.ReadFile(filepath.Join("testdata", "spectrehub_golden.json"))
	if err != nil {
		t.Fatal(err)
	}

	if buf.String() != string(golden) {
		t.Errorf("JSON output does not match golden file.\nGot:\n%s\nWant:\n%s", buf.String(), string(golden))
	}
}

func TestWriteJSON_Empty(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSON(&buf, "empty.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	var report Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if report.Schema != "spectre/v1" {
		t.Errorf("expected schema spectre/v1, got %s", report.Schema)
	}
	if report.Target.Type != "dns-zone" {
		t.Errorf("expected target type dns-zone, got %s", report.Target.Type)
	}
	if report.Target.Name != "empty.com" {
		t.Errorf("expected target name empty.com, got %s", report.Target.Name)
	}
	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(report.Findings))
	}
	if report.Summary.Total != 0 {
		t.Errorf("expected total 0, got %d", report.Summary.Total)
	}
}

func TestWriteJSON_AllSeverities(t *testing.T) {
	findings := []analyzer.Finding{
		{Type: analyzer.SubdomainTakeoverRisk, Severity: analyzer.SeverityCritical, Domain: "a.com", Record: analyzer.Record{Name: "a.com", Type: "CNAME"}},
		{Type: analyzer.DanglingCNAME, Severity: analyzer.SeverityHigh, Domain: "b.com", Record: analyzer.Record{Name: "b.com", Type: "CNAME"}},
		{Type: analyzer.DanglingMX, Severity: analyzer.SeverityMedium, Domain: "c.com", Record: analyzer.Record{Name: "c.com", Type: "MX"}},
		{Type: analyzer.NoCAARecord, Severity: analyzer.SeverityLow, Domain: "d.com", Record: analyzer.Record{Name: "d.com", Type: "CAA"}},
	}

	var buf bytes.Buffer
	err := WriteJSON(&buf, "test.com", findings)
	if err != nil {
		t.Fatal(err)
	}

	var report Report
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if report.Summary.Total != 4 {
		t.Errorf("expected total 4, got %d", report.Summary.Total)
	}
	if report.Summary.Critical != 1 {
		t.Errorf("expected 1 critical, got %d", report.Summary.Critical)
	}
	if report.Summary.High != 1 {
		t.Errorf("expected 1 high, got %d", report.Summary.High)
	}
	if report.Summary.Medium != 1 {
		t.Errorf("expected 1 medium, got %d", report.Summary.Medium)
	}
	if report.Summary.Low != 1 {
		t.Errorf("expected 1 low, got %d", report.Summary.Low)
	}
	if report.Summary.Info != 0 {
		t.Errorf("expected 0 info, got %d", report.Summary.Info)
	}
}
