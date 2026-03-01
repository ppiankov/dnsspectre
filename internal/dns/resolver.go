package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

// CAARecord represents a single DNS CAA record.
type CAARecord struct {
	Flag  uint8
	Tag   string
	Value string
}

// Result holds the outcome of a DNS resolution.
type Result struct {
	Domain string
	RRType uint16
	IPs    []net.IP
	CNAME  string
	Hosts  []string
	Texts  []string
	CAAs   []CAARecord
	Rcode  int
}

// Resolver is the interface for DNS record resolution.
type Resolver interface {
	ResolveA(ctx context.Context, domain string) (*Result, error)
	ResolveAAAA(ctx context.Context, domain string) (*Result, error)
	ResolveCNAME(ctx context.Context, domain string) (*Result, error)
	ResolveMX(ctx context.Context, domain string) (*Result, error)
	ResolveNS(ctx context.Context, domain string) (*Result, error)
	ResolveTXT(ctx context.Context, domain string) (*Result, error)
	ResolveCAA(ctx context.Context, domain string) (*Result, error)
}

// DNSResolver implements Resolver using miekg/dns.
type DNSResolver struct {
	server  string
	timeout time.Duration
	client  *mdns.Client
}

// ResolverOption configures a DNSResolver.
type ResolverOption func(*DNSResolver)

// WithServer sets a custom DNS server address.
func WithServer(addr string) ResolverOption {
	return func(r *DNSResolver) {
		r.server = addr
	}
}

// WithTimeout sets the default resolution timeout.
func WithTimeout(d time.Duration) ResolverOption {
	return func(r *DNSResolver) {
		r.timeout = d
	}
}

// NewResolver creates a DNSResolver.
func NewResolver(opts ...ResolverOption) (*DNSResolver, error) {
	r := &DNSResolver{
		timeout: 5 * time.Second,
		client:  &mdns.Client{Net: "udp"},
	}
	for _, opt := range opts {
		opt(r)
	}
	if r.server == "" {
		server, err := systemResolver()
		if err != nil {
			return nil, fmt.Errorf("discover system resolver: %w", err)
		}
		r.server = server
	}
	return r, nil
}

func systemResolver() (string, error) {
	config, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", err
	}
	if len(config.Servers) == 0 {
		return "", fmt.Errorf("no nameservers in /etc/resolv.conf")
	}
	return net.JoinHostPort(config.Servers[0], config.Port), nil
}

func (r *DNSResolver) query(ctx context.Context, domain string, rrtype uint16) (*mdns.Msg, error) {
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(domain), rrtype)
	msg.RecursionDesired = true

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}

	resp, _, err := r.client.ExchangeContext(ctx, msg, r.server)
	if err != nil {
		return nil, fmt.Errorf("dns query %s %s: %w", domain, mdns.TypeToString[rrtype], err)
	}
	return resp, nil
}

func (r *DNSResolver) ResolveA(ctx context.Context, domain string) (*Result, error) {
	resp, err := r.query(ctx, domain, mdns.TypeA)
	if err != nil {
		return nil, err
	}
	result := &Result{Domain: domain, RRType: mdns.TypeA, Rcode: resp.Rcode}
	for _, ans := range resp.Answer {
		if a, ok := ans.(*mdns.A); ok {
			result.IPs = append(result.IPs, a.A)
		}
	}
	return result, nil
}

func (r *DNSResolver) ResolveAAAA(ctx context.Context, domain string) (*Result, error) {
	resp, err := r.query(ctx, domain, mdns.TypeAAAA)
	if err != nil {
		return nil, err
	}
	result := &Result{Domain: domain, RRType: mdns.TypeAAAA, Rcode: resp.Rcode}
	for _, ans := range resp.Answer {
		if aaaa, ok := ans.(*mdns.AAAA); ok {
			result.IPs = append(result.IPs, aaaa.AAAA)
		}
	}
	return result, nil
}

func (r *DNSResolver) ResolveCNAME(ctx context.Context, domain string) (*Result, error) {
	resp, err := r.query(ctx, domain, mdns.TypeCNAME)
	if err != nil {
		return nil, err
	}
	result := &Result{Domain: domain, RRType: mdns.TypeCNAME, Rcode: resp.Rcode}
	for _, ans := range resp.Answer {
		if cname, ok := ans.(*mdns.CNAME); ok {
			result.CNAME = strings.TrimSuffix(cname.Target, ".")
			break
		}
	}
	return result, nil
}

func (r *DNSResolver) ResolveMX(ctx context.Context, domain string) (*Result, error) {
	resp, err := r.query(ctx, domain, mdns.TypeMX)
	if err != nil {
		return nil, err
	}
	result := &Result{Domain: domain, RRType: mdns.TypeMX, Rcode: resp.Rcode}
	for _, ans := range resp.Answer {
		if mx, ok := ans.(*mdns.MX); ok {
			result.Hosts = append(result.Hosts, strings.TrimSuffix(mx.Mx, "."))
		}
	}
	return result, nil
}

func (r *DNSResolver) ResolveNS(ctx context.Context, domain string) (*Result, error) {
	resp, err := r.query(ctx, domain, mdns.TypeNS)
	if err != nil {
		return nil, err
	}
	result := &Result{Domain: domain, RRType: mdns.TypeNS, Rcode: resp.Rcode}
	for _, ans := range resp.Answer {
		if ns, ok := ans.(*mdns.NS); ok {
			result.Hosts = append(result.Hosts, strings.TrimSuffix(ns.Ns, "."))
		}
	}
	return result, nil
}

func (r *DNSResolver) ResolveTXT(ctx context.Context, domain string) (*Result, error) {
	resp, err := r.query(ctx, domain, mdns.TypeTXT)
	if err != nil {
		return nil, err
	}
	result := &Result{Domain: domain, RRType: mdns.TypeTXT, Rcode: resp.Rcode}
	for _, ans := range resp.Answer {
		if txt, ok := ans.(*mdns.TXT); ok {
			result.Texts = append(result.Texts, strings.Join(txt.Txt, ""))
		}
	}
	return result, nil
}

func (r *DNSResolver) ResolveCAA(ctx context.Context, domain string) (*Result, error) {
	resp, err := r.query(ctx, domain, mdns.TypeCAA)
	if err != nil {
		return nil, err
	}
	result := &Result{Domain: domain, RRType: mdns.TypeCAA, Rcode: resp.Rcode}
	for _, ans := range resp.Answer {
		if caa, ok := ans.(*mdns.CAA); ok {
			result.CAAs = append(result.CAAs, CAARecord{
				Flag:  caa.Flag,
				Tag:   caa.Tag,
				Value: caa.Value,
			})
		}
	}
	return result, nil
}
