package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// HostedZone represents a Route53 hosted zone.
type HostedZone struct {
	ID    string
	Name  string
	Count int64
}

// Record represents a DNS record from Route53.
type Record struct {
	Name   string
	Type   string
	Values []string
	TTL    int64
}

// supportedTypes are the record types we care about for DNS hygiene scanning.
var supportedTypes = map[r53types.RRType]bool{
	r53types.RRTypeA:     true,
	r53types.RRTypeAaaa:  true,
	r53types.RRTypeCname: true,
	r53types.RRTypeMx:    true,
	r53types.RRTypeNs:    true,
	r53types.RRTypeTxt:   true,
	r53types.RRTypeCaa:   true,
}

// Route53API is the subset of the Route53 client we use.
type Route53API interface {
	ListHostedZones(ctx context.Context, params *route53.ListHostedZonesInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ListResourceRecordSets(ctx context.Context, params *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

// Scanner fetches DNS records from AWS Route53.
type Scanner struct {
	client Route53API
}

// NewScanner creates a Scanner with the given Route53 API client.
func NewScanner(client Route53API) *Scanner {
	return &Scanner{client: client}
}

// NewScannerFromConfig creates a Scanner using default AWS credentials.
func NewScannerFromConfig(ctx context.Context) (*Scanner, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	return &Scanner{client: route53.NewFromConfig(cfg)}, nil
}

// ListHostedZones returns all hosted zones with pagination.
func (s *Scanner) ListHostedZones(ctx context.Context) ([]HostedZone, error) {
	var zones []HostedZone
	input := &route53.ListHostedZonesInput{}

	for {
		out, err := s.client.ListHostedZones(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list hosted zones: %w", err)
		}
		for _, z := range out.HostedZones {
			zones = append(zones, HostedZone{
				ID:    stripZoneIDPrefix(aws.ToString(z.Id)),
				Name:  strings.TrimSuffix(aws.ToString(z.Name), "."),
				Count: aws.ToInt64(z.ResourceRecordSetCount),
			})
		}
		if !out.IsTruncated {
			break
		}
		input.Marker = out.NextMarker
	}
	return zones, nil
}

// ListRecords returns all supported DNS records for a hosted zone.
func (s *Scanner) ListRecords(ctx context.Context, zoneID string) ([]Record, error) {
	var records []Record
	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
	}

	for {
		out, err := s.client.ListResourceRecordSets(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list records for zone %s: %w", zoneID, err)
		}
		for _, rrs := range out.ResourceRecordSets {
			if !supportedTypes[rrs.Type] {
				continue
			}
			rec := Record{
				Name: strings.TrimSuffix(aws.ToString(rrs.Name), "."),
				Type: string(rrs.Type),
			}
			if rrs.TTL != nil {
				rec.TTL = *rrs.TTL
			}
			if rrs.AliasTarget != nil {
				rec.Values = []string{strings.TrimSuffix(aws.ToString(rrs.AliasTarget.DNSName), ".")}
			} else {
				for _, rr := range rrs.ResourceRecords {
					rec.Values = append(rec.Values, aws.ToString(rr.Value))
				}
			}
			records = append(records, rec)
		}
		if !out.IsTruncated {
			break
		}
		input.StartRecordName = out.NextRecordName
		input.StartRecordType = out.NextRecordType
		input.StartRecordIdentifier = out.NextRecordIdentifier
	}
	return records, nil
}

func stripZoneIDPrefix(id string) string {
	return strings.TrimPrefix(id, "/hostedzone/")
}
