package gcp

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
)

// ManagedZone represents a GCP Cloud DNS managed zone.
type ManagedZone struct {
	Name        string
	DNSName     string
	Description string
}

// Record represents a DNS record from GCP Cloud DNS.
type Record struct {
	Name   string
	Type   string
	Values []string
	TTL    int64
}

var supportedTypes = map[string]bool{
	"A":     true,
	"AAAA":  true,
	"CNAME": true,
	"MX":    true,
	"NS":    true,
	"TXT":   true,
	"CAA":   true,
}

// CloudDNSAPI is the subset of the Cloud DNS API we use.
type CloudDNSAPI interface {
	ListManagedZones(ctx context.Context, project, pageToken string) (*dns.ManagedZonesListResponse, error)
	ListRecordSets(ctx context.Context, project, zone, pageToken string) (*dns.ResourceRecordSetsListResponse, error)
}

// Scanner fetches DNS records from GCP Cloud DNS.
type Scanner struct {
	client CloudDNSAPI
}

// NewScanner creates a Scanner with the given Cloud DNS API client.
func NewScanner(client CloudDNSAPI) *Scanner {
	return &Scanner{client: client}
}

type cloudDNSAdapter struct {
	svc *dns.Service
}

func (a *cloudDNSAdapter) ListManagedZones(ctx context.Context, project, pageToken string) (*dns.ManagedZonesListResponse, error) {
	call := a.svc.ManagedZones.List(project).Context(ctx)
	if pageToken != "" {
		call = call.PageToken(pageToken)
	}
	return call.Do()
}

func (a *cloudDNSAdapter) ListRecordSets(ctx context.Context, project, zone, pageToken string) (*dns.ResourceRecordSetsListResponse, error) {
	call := a.svc.ResourceRecordSets.List(project, zone).Context(ctx)
	if pageToken != "" {
		call = call.PageToken(pageToken)
	}
	return call.Do()
}

// NewScannerFromConfig creates a Scanner using default GCP credentials.
func NewScannerFromConfig(ctx context.Context) (*Scanner, error) {
	svc, err := dns.NewService(ctx, option.WithScopes(dns.NdevClouddnsReadonlyScope))
	if err != nil {
		return nil, fmt.Errorf("create cloud dns service: %w", err)
	}
	return &Scanner{client: &cloudDNSAdapter{svc: svc}}, nil
}

// ListZones returns all managed zones for a GCP project.
func (s *Scanner) ListZones(ctx context.Context, project string) ([]ManagedZone, error) {
	var zones []ManagedZone
	pageToken := ""

	for {
		out, err := s.client.ListManagedZones(ctx, project, pageToken)
		if err != nil {
			return nil, fmt.Errorf("list managed zones: %w", err)
		}
		for _, z := range out.ManagedZones {
			zones = append(zones, ManagedZone{
				Name:        z.Name,
				DNSName:     strings.TrimSuffix(z.DnsName, "."),
				Description: z.Description,
			})
		}
		if out.NextPageToken == "" {
			break
		}
		pageToken = out.NextPageToken
	}
	return zones, nil
}

// ListRecords returns all supported DNS records for a managed zone.
func (s *Scanner) ListRecords(ctx context.Context, project, zone string) ([]Record, error) {
	var records []Record
	pageToken := ""

	for {
		out, err := s.client.ListRecordSets(ctx, project, zone, pageToken)
		if err != nil {
			return nil, fmt.Errorf("list records for zone %s: %w", zone, err)
		}
		for _, rrs := range out.Rrsets {
			if !supportedTypes[rrs.Type] {
				continue
			}
			records = append(records, Record{
				Name:   strings.TrimSuffix(rrs.Name, "."),
				Type:   rrs.Type,
				Values: rrs.Rrdatas,
				TTL:    rrs.Ttl,
			})
		}
		if out.NextPageToken == "" {
			break
		}
		pageToken = out.NextPageToken
	}
	return records, nil
}
