package dns

import (
	"context"
	"net"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

type testHandler struct {
	responses map[string][]mdns.RR
}

func (h *testHandler) ServeDNS(w mdns.ResponseWriter, r *mdns.Msg) {
	m := new(mdns.Msg)
	m.SetReply(r)
	if len(r.Question) > 0 {
		q := r.Question[0]
		key := q.Name + mdns.TypeToString[q.Qtype]
		if rrs, ok := h.responses[key]; ok {
			m.Answer = rrs
		} else {
			m.Rcode = mdns.RcodeNameError
		}
	}
	_ = w.WriteMsg(m)
}

func startTestDNSServer(t *testing.T, handler mdns.Handler) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &mdns.Server{
		PacketConn: pc,
		Handler:    handler,
	}
	started := make(chan struct{})
	go func() {
		close(started)
		_ = server.ActivateAndServe()
	}()
	<-started
	// Small sleep to let the goroutine start serving.
	time.Sleep(10 * time.Millisecond)
	t.Cleanup(func() { _ = server.Shutdown() })
	return pc.LocalAddr().String()
}

func TestResolveA(t *testing.T) {
	h := &testHandler{responses: map[string][]mdns.RR{
		"example.com.A": {
			&mdns.A{Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
				A: net.ParseIP("93.184.216.34")},
		},
	}}
	addr := startTestDNSServer(t, h)

	r, err := NewResolver(WithServer(addr), WithTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.ResolveA(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if result.Rcode != mdns.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", result.Rcode)
	}
	if len(result.IPs) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(result.IPs))
	}
	if !result.IPs[0].Equal(net.ParseIP("93.184.216.34")) {
		t.Errorf("unexpected IP: %s", result.IPs[0])
	}
}

func TestResolveAAAA(t *testing.T) {
	h := &testHandler{responses: map[string][]mdns.RR{
		"example.com.AAAA": {
			&mdns.AAAA{Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 300},
				AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")},
		},
	}}
	addr := startTestDNSServer(t, h)

	r, err := NewResolver(WithServer(addr), WithTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.ResolveAAAA(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.IPs) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(result.IPs))
	}
	if !result.IPs[0].Equal(net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")) {
		t.Errorf("unexpected IP: %s", result.IPs[0])
	}
}

func TestResolveCNAME(t *testing.T) {
	h := &testHandler{responses: map[string][]mdns.RR{
		"app.example.com.CNAME": {
			&mdns.CNAME{Hdr: mdns.RR_Header{Name: "app.example.com.", Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 300},
				Target: "myapp.herokuapp.com."},
		},
	}}
	addr := startTestDNSServer(t, h)

	r, err := NewResolver(WithServer(addr), WithTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.ResolveCNAME(context.Background(), "app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if result.CNAME != "myapp.herokuapp.com" {
		t.Errorf("expected myapp.herokuapp.com, got %s", result.CNAME)
	}
}

func TestResolveMX(t *testing.T) {
	h := &testHandler{responses: map[string][]mdns.RR{
		"example.com.MX": {
			&mdns.MX{Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeMX, Class: mdns.ClassINET, Ttl: 300},
				Preference: 10, Mx: "mail.example.com."},
		},
	}}
	addr := startTestDNSServer(t, h)

	r, err := NewResolver(WithServer(addr), WithTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.ResolveMX(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Hosts) != 1 || result.Hosts[0] != "mail.example.com" {
		t.Errorf("unexpected MX hosts: %v", result.Hosts)
	}
}

func TestResolveNS(t *testing.T) {
	h := &testHandler{responses: map[string][]mdns.RR{
		"example.com.NS": {
			&mdns.NS{Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 300},
				Ns: "ns1.example.com."},
		},
	}}
	addr := startTestDNSServer(t, h)

	r, err := NewResolver(WithServer(addr), WithTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.ResolveNS(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Hosts) != 1 || result.Hosts[0] != "ns1.example.com" {
		t.Errorf("unexpected NS hosts: %v", result.Hosts)
	}
}

func TestResolveTXT(t *testing.T) {
	h := &testHandler{responses: map[string][]mdns.RR{
		"example.com.TXT": {
			&mdns.TXT{Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 300},
				Txt: []string{"v=spf1 include:_spf.google.com ~all"}},
		},
	}}
	addr := startTestDNSServer(t, h)

	r, err := NewResolver(WithServer(addr), WithTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.ResolveTXT(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Texts) != 1 || result.Texts[0] != "v=spf1 include:_spf.google.com ~all" {
		t.Errorf("unexpected TXT: %v", result.Texts)
	}
}

func TestResolveCAA(t *testing.T) {
	h := &testHandler{responses: map[string][]mdns.RR{
		"example.com.CAA": {
			&mdns.CAA{Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeCAA, Class: mdns.ClassINET, Ttl: 300},
				Flag: 0, Tag: "issue", Value: "letsencrypt.org"},
		},
	}}
	addr := startTestDNSServer(t, h)

	r, err := NewResolver(WithServer(addr), WithTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.ResolveCAA(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.CAAs) != 1 {
		t.Fatalf("expected 1 CAA, got %d", len(result.CAAs))
	}
	if result.CAAs[0].Tag != "issue" || result.CAAs[0].Value != "letsencrypt.org" {
		t.Errorf("unexpected CAA: %+v", result.CAAs[0])
	}
}

func TestResolve_NXDOMAIN(t *testing.T) {
	h := &testHandler{responses: map[string][]mdns.RR{}}
	addr := startTestDNSServer(t, h)

	r, err := NewResolver(WithServer(addr), WithTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.ResolveA(context.Background(), "nonexistent.example.com")
	if err != nil {
		t.Fatalf("NXDOMAIN should not return error, got: %v", err)
	}
	if result.Rcode != mdns.RcodeNameError {
		t.Errorf("expected NXDOMAIN rcode, got %d", result.Rcode)
	}
	if len(result.IPs) != 0 {
		t.Errorf("expected no IPs for NXDOMAIN, got %d", len(result.IPs))
	}
}

func TestResolve_ContextCancel(t *testing.T) {
	h := &testHandler{responses: map[string][]mdns.RR{}}
	addr := startTestDNSServer(t, h)

	r, err := NewResolver(WithServer(addr), WithTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = r.ResolveA(ctx, "example.com")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}
