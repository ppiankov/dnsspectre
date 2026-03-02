package cloudflare

import (
	"context"
	"fmt"

	cfclient "github.com/cloudflare/cloudflare-go/v4"
	cfdns "github.com/cloudflare/cloudflare-go/v4/dns"
	"github.com/cloudflare/cloudflare-go/v4/option"
	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
)

// Zone represents a Cloudflare DNS zone.
type Zone struct {
	ID   string
	Name string
}

// Record represents a DNS record from Cloudflare.
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

// CloudflareAPI is the subset of the Cloudflare API we use.
type CloudflareAPI interface {
	ListZones(ctx context.Context) ([]cfzones.Zone, error)
	ListDNSRecords(ctx context.Context, zoneID string) ([]cfdns.RecordResponse, error)
}

// Scanner fetches DNS records from Cloudflare.
type Scanner struct {
	client CloudflareAPI
}

// NewScanner creates a Scanner with the given Cloudflare API client.
func NewScanner(client CloudflareAPI) *Scanner {
	return &Scanner{client: client}
}

type cloudflareAdapter struct {
	client *cfclient.Client
}

func (a *cloudflareAdapter) ListZones(ctx context.Context) ([]cfzones.Zone, error) {
	var zones []cfzones.Zone
	pager := a.client.Zones.ListAutoPaging(ctx, cfzones.ZoneListParams{})
	for pager.Next() {
		zones = append(zones, pager.Current())
	}
	if err := pager.Err(); err != nil {
		return nil, err
	}
	return zones, nil
}

func (a *cloudflareAdapter) ListDNSRecords(ctx context.Context, zoneID string) ([]cfdns.RecordResponse, error) {
	var records []cfdns.RecordResponse
	pager := a.client.DNS.Records.ListAutoPaging(ctx, cfdns.RecordListParams{
		ZoneID: cfclient.F(zoneID),
	})
	for pager.Next() {
		records = append(records, pager.Current())
	}
	if err := pager.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

// NewScannerFromConfig creates a Scanner using a Cloudflare API token.
func NewScannerFromConfig(apiToken string) (*Scanner, error) {
	client := cfclient.NewClient(option.WithAPIToken(apiToken))
	return &Scanner{client: &cloudflareAdapter{client: client}}, nil
}

// ListZones returns all DNS zones accessible by the API token.
func (s *Scanner) ListZones(ctx context.Context) ([]Zone, error) {
	cfZones, err := s.client.ListZones(ctx)
	if err != nil {
		return nil, fmt.Errorf("list cloudflare zones: %w", err)
	}
	var zones []Zone
	for _, z := range cfZones {
		zones = append(zones, Zone{
			ID:   z.ID,
			Name: z.Name,
		})
	}
	return zones, nil
}

// ListRecords returns all supported DNS records for a zone.
func (s *Scanner) ListRecords(ctx context.Context, zoneID string) ([]Record, error) {
	cfRecords, err := s.client.ListDNSRecords(ctx, zoneID)
	if err != nil {
		return nil, fmt.Errorf("list records for zone %s: %w", zoneID, err)
	}
	var records []Record
	for _, r := range cfRecords {
		recType := string(r.Type)
		if !supportedTypes[recType] {
			continue
		}
		rec := Record{
			Name:   r.Name,
			Type:   recType,
			TTL:    int64(r.TTL),
			Values: extractValues(r),
		}
		records = append(records, rec)
	}
	return records, nil
}

func extractValues(r cfdns.RecordResponse) []string {
	recType := string(r.Type)
	switch recType {
	case "MX":
		return []string{fmt.Sprintf("%d %s", int(r.Priority), r.Content)}
	default:
		if r.Content != "" {
			return []string{r.Content}
		}
		return nil
	}
}
