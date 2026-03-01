package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
)

// Zone represents an Azure DNS zone.
type Zone struct {
	Name          string
	ResourceGroup string
}

// Record represents a DNS record from Azure DNS.
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

// AzureDNSAPI is the subset of the Azure DNS API we use.
type AzureDNSAPI interface {
	ListZones(ctx context.Context) ([]armdns.Zone, error)
	ListRecordSets(ctx context.Context, resourceGroup, zoneName string) ([]armdns.RecordSet, error)
}

// Scanner fetches DNS records from Azure DNS.
type Scanner struct {
	client AzureDNSAPI
}

// NewScanner creates a Scanner with the given Azure DNS API client.
func NewScanner(client AzureDNSAPI) *Scanner {
	return &Scanner{client: client}
}

type azureDNSAdapter struct {
	zones      *armdns.ZonesClient
	recordSets *armdns.RecordSetsClient
}

func (a *azureDNSAdapter) ListZones(ctx context.Context) ([]armdns.Zone, error) {
	var zones []armdns.Zone
	pager := a.zones.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, z := range page.Value {
			if z != nil {
				zones = append(zones, *z)
			}
		}
	}
	return zones, nil
}

func (a *azureDNSAdapter) ListRecordSets(ctx context.Context, resourceGroup, zoneName string) ([]armdns.RecordSet, error) {
	var sets []armdns.RecordSet
	pager := a.recordSets.NewListAllByDNSZonePager(resourceGroup, zoneName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, rs := range page.Value {
			if rs != nil {
				sets = append(sets, *rs)
			}
		}
	}
	return sets, nil
}

// NewScannerFromConfig creates a Scanner using default Azure credentials.
func NewScannerFromConfig(ctx context.Context, subscriptionID string) (*Scanner, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("create azure credential: %w", err)
	}
	zonesClient, err := armdns.NewZonesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("create zones client: %w", err)
	}
	recordSetsClient, err := armdns.NewRecordSetsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("create record sets client: %w", err)
	}
	_ = ctx // credentials are validated on first API call
	return &Scanner{client: &azureDNSAdapter{zones: zonesClient, recordSets: recordSetsClient}}, nil
}

// ListZones returns all DNS zones in the subscription.
func (s *Scanner) ListZones(ctx context.Context) ([]Zone, error) {
	azureZones, err := s.client.ListZones(ctx)
	if err != nil {
		return nil, fmt.Errorf("list dns zones: %w", err)
	}
	var zones []Zone
	for _, z := range azureZones {
		name := deref(z.Name)
		zones = append(zones, Zone{
			Name:          name,
			ResourceGroup: extractResourceGroup(deref(z.ID)),
		})
	}
	return zones, nil
}

// ListRecords returns all supported DNS records for a zone.
func (s *Scanner) ListRecords(ctx context.Context, resourceGroup, zoneName string) ([]Record, error) {
	sets, err := s.client.ListRecordSets(ctx, resourceGroup, zoneName)
	if err != nil {
		return nil, fmt.Errorf("list records for zone %s: %w", zoneName, err)
	}
	var records []Record
	for _, rs := range sets {
		recType := extractRecordType(deref(rs.Type))
		if !supportedTypes[recType] {
			continue
		}
		rec := Record{
			Name: deref(rs.Name),
			Type: recType,
		}
		if rs.Properties != nil {
			if rs.Properties.TTL != nil {
				rec.TTL = *rs.Properties.TTL
			}
			rec.Values = extractValues(recType, rs.Properties)
		}
		records = append(records, rec)
	}
	return records, nil
}

func extractValues(recType string, props *armdns.RecordSetProperties) []string {
	var vals []string
	switch recType {
	case "A":
		for _, r := range props.ARecords {
			if r != nil {
				vals = append(vals, deref(r.IPv4Address))
			}
		}
	case "AAAA":
		for _, r := range props.AaaaRecords {
			if r != nil {
				vals = append(vals, deref(r.IPv6Address))
			}
		}
	case "CNAME":
		if props.CnameRecord != nil {
			vals = append(vals, deref(props.CnameRecord.Cname))
		}
	case "MX":
		for _, r := range props.MxRecords {
			if r != nil {
				vals = append(vals, fmt.Sprintf("%d %s", derefInt32(r.Preference), deref(r.Exchange)))
			}
		}
	case "NS":
		for _, r := range props.NsRecords {
			if r != nil {
				vals = append(vals, deref(r.Nsdname))
			}
		}
	case "TXT":
		for _, r := range props.TxtRecords {
			if r != nil {
				var parts []string
				for _, v := range r.Value {
					if v != nil {
						parts = append(parts, *v)
					}
				}
				vals = append(vals, strings.Join(parts, ""))
			}
		}
	case "CAA":
		for _, r := range props.CaaRecords {
			if r != nil {
				vals = append(vals, fmt.Sprintf("%d %s %s", derefInt32(r.Flags), deref(r.Tag), deref(r.Value)))
			}
		}
	}
	return vals
}

// extractRecordType strips "Microsoft.Network/dnszones/" prefix from Azure record type.
func extractRecordType(fullType string) string {
	parts := strings.Split(fullType, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullType
}

// extractResourceGroup extracts the resource group from an Azure resource ID.
func extractResourceGroup(id string) string {
	parts := strings.Split(id, "/")
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefInt32(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}
