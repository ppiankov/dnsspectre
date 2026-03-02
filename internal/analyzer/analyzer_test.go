package analyzer

import (
	"context"
	"errors"
	"net"
	"testing"

	mdns "github.com/miekg/dns"

	"github.com/ppiankov/dnsspectre/internal/dns"
)

type mockResolver struct {
	responses map[string]*dns.Result
	errs      map[string]error
}

func (m *mockResolver) resolve(domain, rrType string) (*dns.Result, error) {
	key := domain + ":" + rrType
	if err, ok := m.errs[key]; ok {
		return nil, err
	}
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

func TestNew(t *testing.T) {
	a := New(&mockResolver{}, nil)
	if a == nil {
		t.Fatal("New returned nil")
	}
}

func TestAnalyze_DanglingCNAME(t *testing.T) {
	mock := &mockResolver{responses: map[string]*dns.Result{}}
	// "old.nxdomain.test" not in responses → defaults to NXDOMAIN
	a := New(mock, nil)
	records := []Record{
		{Name: "app.example.com", Type: "CNAME", Values: []string{"old.nxdomain.test"}},
		{Name: "app.example.com", Type: "CAA", Values: []string{"0 issue letsencrypt.org"}},
	}
	findings, err := a.Analyze(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != DanglingCNAME {
		t.Errorf("expected DANGLING_CNAME, got %s", findings[0].Type)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
	if findings[0].Target != "old.nxdomain.test" {
		t.Errorf("expected target old.nxdomain.test, got %s", findings[0].Target)
	}
}

func TestAnalyze_SubdomainTakeoverRisk(t *testing.T) {
	mock := &mockResolver{responses: map[string]*dns.Result{}}
	// "old.s3.amazonaws.com" not in responses → NXDOMAIN
	a := New(mock, dns.BuiltinFingerprints())
	records := []Record{
		{Name: "cdn.example.com", Type: "CNAME", Values: []string{"old.s3.amazonaws.com"}},
		{Name: "cdn.example.com", Type: "CAA", Values: []string{"0 issue letsencrypt.org"}},
	}
	findings, err := a.Analyze(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != SubdomainTakeoverRisk {
		t.Errorf("expected SUBDOMAIN_TAKEOVER_RISK, got %s", findings[0].Type)
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
	}
	if findings[0].Service != "AWS S3" {
		t.Errorf("expected service AWS S3, got %s", findings[0].Service)
	}
}

func TestAnalyze_FingerprintNoNXDomain(t *testing.T) {
	mock := &mockResolver{responses: map[string]*dns.Result{}}
	// Use only Shopify fingerprint (NXDomain=false)
	fps := []dns.Fingerprint{
		{
			Service:      "Shopify",
			CNAMEs:       []string{".myshopify.com"},
			StatusCodes:  []int{404},
			BodyPatterns: []string{"Sorry, this shop is currently unavailable"},
			NXDomain:     false,
		},
	}
	a := New(mock, fps)
	records := []Record{
		{Name: "shop.example.com", Type: "CNAME", Values: []string{"old.myshopify.com"}},
		{Name: "shop.example.com", Type: "CAA", Values: []string{"0 issue letsencrypt.org"}},
	}
	findings, err := a.Analyze(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != DanglingCNAME {
		t.Errorf("expected DANGLING_CNAME (not takeover), got %s", findings[0].Type)
	}
}

func TestAnalyze_CNAMEResolves(t *testing.T) {
	mock := &mockResolver{
		responses: map[string]*dns.Result{
			"live.example.com:A": {Domain: "live.example.com", Rcode: mdns.RcodeSuccess, IPs: []net.IP{net.ParseIP("1.2.3.4")}},
		},
	}
	a := New(mock, dns.BuiltinFingerprints())
	records := []Record{
		{Name: "app.example.com", Type: "CNAME", Values: []string{"live.example.com"}},
		{Name: "app.example.com", Type: "CAA", Values: []string{"0 issue letsencrypt.org"}},
	}
	findings, err := a.Analyze(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestAnalyze_CNAMEResolverError(t *testing.T) {
	mock := &mockResolver{
		responses: map[string]*dns.Result{},
		errs: map[string]error{
			"broken.test:A": errors.New("network timeout"),
		},
	}
	a := New(mock, nil)
	records := []Record{
		{Name: "app.example.com", Type: "CNAME", Values: []string{"broken.test"}},
		{Name: "app.example.com", Type: "CAA", Values: []string{"0 issue letsencrypt.org"}},
	}
	findings, err := a.Analyze(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (error skipped), got %d", len(findings))
	}
}

func TestAnalyze_DanglingMX(t *testing.T) {
	mock := &mockResolver{responses: map[string]*dns.Result{}}
	a := New(mock, nil)
	records := []Record{
		{Name: "example.com", Type: "MX", Values: []string{"10 mail.dead.test"}},
		{Name: "example.com", Type: "CAA", Values: []string{"0 issue letsencrypt.org"}},
	}
	findings, err := a.Analyze(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != DanglingMX {
		t.Errorf("expected DANGLING_MX, got %s", findings[0].Type)
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("expected MEDIUM severity, got %s", findings[0].Severity)
	}
	if findings[0].Target != "mail.dead.test" {
		t.Errorf("expected target mail.dead.test, got %s", findings[0].Target)
	}
}

func TestAnalyze_MXResolves(t *testing.T) {
	mock := &mockResolver{
		responses: map[string]*dns.Result{
			"mail.example.com:A": {Domain: "mail.example.com", Rcode: mdns.RcodeSuccess, IPs: []net.IP{net.ParseIP("5.6.7.8")}},
		},
	}
	a := New(mock, nil)
	records := []Record{
		{Name: "example.com", Type: "MX", Values: []string{"10 mail.example.com"}},
		{Name: "example.com", Type: "CAA", Values: []string{"0 issue letsencrypt.org"}},
	}
	findings, err := a.Analyze(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestAnalyze_DanglingNS(t *testing.T) {
	mock := &mockResolver{responses: map[string]*dns.Result{}}
	a := New(mock, nil)
	records := []Record{
		{Name: "example.com", Type: "NS", Values: []string{"ns1.dead-provider.test"}},
		{Name: "example.com", Type: "CAA", Values: []string{"0 issue letsencrypt.org"}},
	}
	findings, err := a.Analyze(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != DanglingNS {
		t.Errorf("expected DANGLING_NS, got %s", findings[0].Type)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
}

func TestAnalyze_NSResolves(t *testing.T) {
	mock := &mockResolver{
		responses: map[string]*dns.Result{
			"ns1.example.com:A": {Domain: "ns1.example.com", Rcode: mdns.RcodeSuccess, IPs: []net.IP{net.ParseIP("9.9.9.9")}},
		},
	}
	a := New(mock, nil)
	records := []Record{
		{Name: "example.com", Type: "NS", Values: []string{"ns1.example.com"}},
		{Name: "example.com", Type: "CAA", Values: []string{"0 issue letsencrypt.org"}},
	}
	findings, err := a.Analyze(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestAnalyze_NoCAARecord(t *testing.T) {
	mock := &mockResolver{
		responses: map[string]*dns.Result{
			"example.com:CAA": {Domain: "example.com", Rcode: mdns.RcodeSuccess, CAAs: nil},
			"example.com:A":   {Domain: "example.com", Rcode: mdns.RcodeSuccess, IPs: []net.IP{net.ParseIP("1.2.3.4")}},
		},
	}
	a := New(mock, nil)
	records := []Record{
		{Name: "example.com", Type: "A", Values: []string{"1.2.3.4"}},
	}
	findings, err := a.Analyze(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != NoCAARecord {
		t.Errorf("expected NO_CAA_RECORD, got %s", findings[0].Type)
	}
	if findings[0].Severity != SeverityLow {
		t.Errorf("expected LOW severity, got %s", findings[0].Severity)
	}
}

func TestAnalyze_CAAExists(t *testing.T) {
	mock := &mockResolver{responses: map[string]*dns.Result{}}
	a := New(mock, nil)
	records := []Record{
		{Name: "example.com", Type: "A", Values: []string{"1.2.3.4"}},
		{Name: "example.com", Type: "CAA", Values: []string{"0 issue letsencrypt.org"}},
	}
	findings, err := a.Analyze(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestAnalyze_CAAExistsInDNS(t *testing.T) {
	mock := &mockResolver{
		responses: map[string]*dns.Result{
			"example.com:CAA": {Domain: "example.com", Rcode: mdns.RcodeSuccess, CAAs: []dns.CAARecord{{Flag: 0, Tag: "issue", Value: "letsencrypt.org"}}},
			"example.com:A":   {Domain: "example.com", Rcode: mdns.RcodeSuccess, IPs: []net.IP{net.ParseIP("1.2.3.4")}},
		},
	}
	a := New(mock, nil)
	records := []Record{
		{Name: "example.com", Type: "A", Values: []string{"1.2.3.4"}},
	}
	findings, err := a.Analyze(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (CAA in DNS), got %d", len(findings))
	}
}

func TestAnalyze_EmptyRecords(t *testing.T) {
	a := New(&mockResolver{}, nil)
	findings, err := a.Analyze(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseMXHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"10 mail.example.com", "mail.example.com"},
		{"10 mail.example.com.", "mail.example.com"},
		{"mail.example.com", "mail.example.com"},
		{"", ""},
	}
	for _, tt := range tests {
		got := parseMXHost(tt.input)
		if got != tt.want {
			t.Errorf("parseMXHost(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
