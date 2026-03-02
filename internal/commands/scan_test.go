package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"

	"github.com/ppiankov/dnsspectre/internal/analyzer"
	"github.com/ppiankov/dnsspectre/internal/aws"
	"github.com/ppiankov/dnsspectre/internal/azure"
	cfpkg "github.com/ppiankov/dnsspectre/internal/cloudflare"
	"github.com/ppiankov/dnsspectre/internal/dns"
	"github.com/ppiankov/dnsspectre/internal/gcp"
	"github.com/ppiankov/dnsspectre/internal/report"
)

// mockResolver implements dns.Resolver for testing.
type mockResolver struct {
	responses map[string]*dns.Result
}

func (m *mockResolver) resolve(domain, rrType string) (*dns.Result, error) {
	key := domain + ":" + rrType
	if r, ok := m.responses[key]; ok {
		return r, nil
	}
	return &dns.Result{Domain: domain, Rcode: mdns.RcodeNameError}, nil
}

func (m *mockResolver) ResolveA(_ context.Context, domain string) (*dns.Result, error) {
	return m.resolve(domain, "A")
}
func (m *mockResolver) ResolveAAAA(_ context.Context, domain string) (*dns.Result, error) {
	return m.resolve(domain, "AAAA")
}
func (m *mockResolver) ResolveCNAME(_ context.Context, domain string) (*dns.Result, error) {
	return m.resolve(domain, "CNAME")
}
func (m *mockResolver) ResolveMX(_ context.Context, domain string) (*dns.Result, error) {
	return m.resolve(domain, "MX")
}
func (m *mockResolver) ResolveNS(_ context.Context, domain string) (*dns.Result, error) {
	return m.resolve(domain, "NS")
}
func (m *mockResolver) ResolveTXT(_ context.Context, domain string) (*dns.Result, error) {
	return m.resolve(domain, "TXT")
}
func (m *mockResolver) ResolveCAA(_ context.Context, domain string) (*dns.Result, error) {
	return m.resolve(domain, "CAA")
}

func TestScanRequiresMode(t *testing.T) {
	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)
	rootCmd.SetArgs([]string{"scan"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when neither --domain nor --platform is set")
	}
	if !strings.Contains(err.Error(), "either --domain or --platform must be specified") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestScanMutuallyExclusive(t *testing.T) {
	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)
	rootCmd.SetArgs([]string{"scan", "--domain", "example.com", "--platform", "aws", "--zone", "Z123"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when both --domain and --platform are set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestScanZoneRequiresPlatform(t *testing.T) {
	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)
	rootCmd.SetArgs([]string{"scan", "--zone", "Z123"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when --zone is set without --platform")
	}
	if !strings.Contains(err.Error(), "--zone requires --platform") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestScanPlatformWithoutZone(t *testing.T) {
	// --platform without --zone should pass flag validation
	// (will fail later on credentials, which is expected)
	opts := &GlobalOptions{Platform: "aws"}
	err := validateScanFlags(opts)
	if err != nil {
		t.Errorf("expected no validation error for --platform without --zone, got: %v", err)
	}
}

func TestScanInvalidPlatform(t *testing.T) {
	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)
	rootCmd.SetArgs([]string{"scan", "--platform", "digitalocean", "--zone", "Z123"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid platform")
	}
	if !strings.Contains(err.Error(), "unsupported platform") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestScanHelp(t *testing.T) {
	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"scan", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	for _, flag := range []string{"--platform", "--domain", "--zone", "--format", "--timeout", "--fingerprints"} {
		if !strings.Contains(output, flag) {
			t.Errorf("scan --help missing flag %s in output", flag)
		}
	}
}

func TestScanDomainMode_TextOutput(t *testing.T) {
	// Mock resolver: CNAME → NXDOMAIN for S3 target, with CAA present
	mock := &mockResolver{responses: map[string]*dns.Result{
		"test.example.com:CNAME": {
			Domain: "test.example.com",
			CNAME:  "dead.s3.amazonaws.com",
			Rcode:  mdns.RcodeSuccess,
		},
		"test.example.com:CAA": {
			Domain: "test.example.com",
			CAAs:   []dns.CAARecord{{Flag: 0, Tag: "issue", Value: "letsencrypt.org"}},
			Rcode:  mdns.RcodeSuccess,
		},
		// A query for the CNAME target returns NXDOMAIN (default behavior)
	}}

	opts := &GlobalOptions{
		Domain: "test.example.com",
		Format: "text",
	}

	var buf bytes.Buffer
	err := runScan(context.Background(), opts, &buf, mock)
	if err != nil {
		t.Fatalf("runScan error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "dnsspectre report for test.example.com") {
		t.Errorf("missing header in output:\n%s", out)
	}
	if !strings.Contains(out, "SUBDOMAIN_TAKEOVER_RISK") {
		t.Errorf("expected SUBDOMAIN_TAKEOVER_RISK finding:\n%s", out)
	}
	if !strings.Contains(out, "AWS S3") {
		t.Errorf("expected AWS S3 service in detail:\n%s", out)
	}
	if !strings.Contains(out, "Summary:") {
		t.Errorf("missing summary line:\n%s", out)
	}
}

func TestScanDomainMode_JSONOutput(t *testing.T) {
	mock := &mockResolver{responses: map[string]*dns.Result{
		"test.example.com:CNAME": {
			Domain: "test.example.com",
			CNAME:  "dead.s3.amazonaws.com",
			Rcode:  mdns.RcodeSuccess,
		},
		"test.example.com:CAA": {
			Domain: "test.example.com",
			CAAs:   []dns.CAARecord{{Flag: 0, Tag: "issue", Value: "letsencrypt.org"}},
			Rcode:  mdns.RcodeSuccess,
		},
	}}

	opts := &GlobalOptions{
		Domain: "test.example.com",
		Format: "json",
	}

	var buf bytes.Buffer
	err := runScan(context.Background(), opts, &buf, mock)
	if err != nil {
		t.Fatalf("runScan error: %v", err)
	}

	var rpt report.Report
	if err := json.Unmarshal(buf.Bytes(), &rpt); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rpt.Schema != "spectre/v1" {
		t.Errorf("expected schema spectre/v1, got %s", rpt.Schema)
	}
	if rpt.Target.Name != "test.example.com" {
		t.Errorf("expected target test.example.com, got %s", rpt.Target.Name)
	}
	if rpt.Summary.Total < 1 {
		t.Errorf("expected at least 1 finding, got %d", rpt.Summary.Total)
	}
	if rpt.Summary.Critical < 1 {
		t.Errorf("expected at least 1 critical finding")
	}
}

func TestScanDomainMode_NoFindings(t *testing.T) {
	// Domain with no DNS records → only CAA check (which we provide)
	mock := &mockResolver{responses: map[string]*dns.Result{
		"clean.example.com:CAA": {
			Domain: "clean.example.com",
			CAAs:   []dns.CAARecord{{Flag: 0, Tag: "issue", Value: "letsencrypt.org"}},
			Rcode:  mdns.RcodeSuccess,
		},
	}}

	opts := &GlobalOptions{
		Domain: "clean.example.com",
		Format: "text",
	}

	var buf bytes.Buffer
	err := runScan(context.Background(), opts, &buf, mock)
	if err != nil {
		t.Fatalf("runScan error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Summary: 0 findings") {
		t.Errorf("expected 0 findings, got:\n%s", out)
	}
}

func TestConvertAWSRecords(t *testing.T) {
	input := []aws.Record{
		{Name: "a.com", Type: "CNAME", Values: []string{"target.com"}, TTL: 300},
	}
	out := convertAWSRecords(input)
	if len(out) != 1 {
		t.Fatalf("expected 1 record, got %d", len(out))
	}
	if out[0].Name != "a.com" || out[0].Type != "CNAME" || out[0].TTL != 300 {
		t.Errorf("unexpected record: %+v", out[0])
	}
}

func TestConvertGCPRecords(t *testing.T) {
	input := []gcp.Record{
		{Name: "b.com", Type: "MX", Values: []string{"10 mail.b.com"}, TTL: 600},
	}
	out := convertGCPRecords(input)
	if len(out) != 1 || out[0].Name != "b.com" || out[0].Type != "MX" {
		t.Errorf("unexpected record: %+v", out)
	}
}

func TestConvertAzureRecords(t *testing.T) {
	input := []azure.Record{
		{Name: "c.com", Type: "NS", Values: []string{"ns1.c.com"}, TTL: 900},
	}
	out := convertAzureRecords(input)
	if len(out) != 1 || out[0].Name != "c.com" || out[0].TTL != 900 {
		t.Errorf("unexpected record: %+v", out)
	}
}

func TestConvertCloudflareRecords(t *testing.T) {
	input := []cfpkg.Record{
		{Name: "d.com", Type: "A", Values: []string{"1.2.3.4"}, TTL: 120},
	}
	out := convertCloudflareRecords(input)
	if len(out) != 1 || out[0].Name != "d.com" || out[0].Values[0] != "1.2.3.4" {
		t.Errorf("unexpected record: %+v", out)
	}
}

func TestDnsQueryRecords(t *testing.T) {
	mock := &mockResolver{responses: map[string]*dns.Result{
		"example.com:CNAME": {
			Domain: "example.com",
			CNAME:  "target.example.com",
			Rcode:  mdns.RcodeSuccess,
		},
		"example.com:MX": {
			Domain: "example.com",
			Hosts:  []string{"mail.example.com"},
			Rcode:  mdns.RcodeSuccess,
		},
		"example.com:NS": {
			Domain: "example.com",
			Hosts:  []string{"ns1.example.com"},
			Rcode:  mdns.RcodeSuccess,
		},
		"example.com:CAA": {
			Domain: "example.com",
			CAAs:   []dns.CAARecord{{Flag: 0, Tag: "issue", Value: "letsencrypt.org"}},
			Rcode:  mdns.RcodeSuccess,
		},
	}}

	records := dnsQueryRecords(context.Background(), mock, "example.com")

	typeCount := make(map[string]int)
	for _, r := range records {
		typeCount[r.Type]++
	}

	if typeCount["CNAME"] != 1 {
		t.Errorf("expected 1 CNAME record, got %d", typeCount["CNAME"])
	}
	if typeCount["MX"] != 1 {
		t.Errorf("expected 1 MX record, got %d", typeCount["MX"])
	}
	if typeCount["NS"] != 1 {
		t.Errorf("expected 1 NS record, got %d", typeCount["NS"])
	}
	if typeCount["CAA"] != 1 {
		t.Errorf("expected 1 CAA record, got %d", typeCount["CAA"])
	}
}

func TestDnsQueryRecords_NoCNAME(t *testing.T) {
	// Domain without CNAME should not produce CNAME records
	mock := &mockResolver{responses: map[string]*dns.Result{
		"example.com:CNAME": {
			Domain: "example.com",
			Rcode:  mdns.RcodeSuccess,
		},
	}}

	records := dnsQueryRecords(context.Background(), mock, "example.com")

	for _, r := range records {
		if r.Type == "CNAME" {
			t.Error("should not produce CNAME record when resolver returns empty CNAME")
		}
	}
}

// Verify the Report type is exported and usable from test code.
var _ = analyzer.Record{}
