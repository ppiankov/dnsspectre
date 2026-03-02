package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ppiankov/dnsspectre/internal/analyzer"
)

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	err := WriteText(&buf, "example.com", testFindings())
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "dnsspectre report for example.com") {
		t.Error("missing header")
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Error("missing CRITICAL severity")
	}
	if !strings.Contains(out, "SUBDOMAIN_TAKEOVER_RISK") {
		t.Error("missing SUBDOMAIN_TAKEOVER_RISK finding type")
	}
	if !strings.Contains(out, "DANGLING_CNAME") {
		t.Error("missing DANGLING_CNAME finding type")
	}
	if !strings.Contains(out, "Summary: 3 findings") {
		t.Errorf("missing summary line, got:\n%s", out)
	}
}

func TestWriteText_Empty(t *testing.T) {
	var buf bytes.Buffer
	err := WriteText(&buf, "empty.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "dnsspectre report for empty.com") {
		t.Error("missing header")
	}
	if !strings.Contains(out, "Summary: 0 findings") {
		t.Errorf("expected 0 findings summary, got:\n%s", out)
	}
}

func TestWriteText_SortBySeverity(t *testing.T) {
	findings := []analyzer.Finding{
		{Type: analyzer.NoCAARecord, Severity: analyzer.SeverityLow, Domain: "low.com", Record: analyzer.Record{Name: "low.com", Type: "CAA"}},
		{Type: analyzer.SubdomainTakeoverRisk, Severity: analyzer.SeverityCritical, Domain: "crit.com", Record: analyzer.Record{Name: "crit.com", Type: "CNAME"}},
	}

	var buf bytes.Buffer
	err := WriteText(&buf, "test.com", findings)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	critIdx := strings.Index(out, "CRITICAL")
	lowIdx := strings.Index(out, "LOW")
	if critIdx < 0 || lowIdx < 0 {
		t.Fatalf("missing severity labels in output:\n%s", out)
	}
	if critIdx > lowIdx {
		t.Error("expected CRITICAL before LOW in output")
	}
}
