package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

type mockRoute53 struct {
	listZonesPages  []*route53.ListHostedZonesOutput
	listZonesIndex  int
	listRecordPages []*route53.ListResourceRecordSetsOutput
	listRecordIndex int
}

func (m *mockRoute53) ListHostedZones(_ context.Context, _ *route53.ListHostedZonesInput, _ ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	if m.listZonesIndex >= len(m.listZonesPages) {
		return &route53.ListHostedZonesOutput{}, nil
	}
	out := m.listZonesPages[m.listZonesIndex]
	m.listZonesIndex++
	return out, nil
}

func (m *mockRoute53) ListResourceRecordSets(_ context.Context, _ *route53.ListResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	if m.listRecordIndex >= len(m.listRecordPages) {
		return &route53.ListResourceRecordSetsOutput{}, nil
	}
	out := m.listRecordPages[m.listRecordIndex]
	m.listRecordIndex++
	return out, nil
}

func TestListHostedZones(t *testing.T) {
	mock := &mockRoute53{
		listZonesPages: []*route53.ListHostedZonesOutput{
			{
				HostedZones: []r53types.HostedZone{
					{Id: aws.String("/hostedzone/Z111"), Name: aws.String("example.com."), ResourceRecordSetCount: aws.Int64(10)},
					{Id: aws.String("/hostedzone/Z222"), Name: aws.String("test.com."), ResourceRecordSetCount: aws.Int64(5)},
				},
				IsTruncated: false,
			},
		},
	}
	s := NewScanner(mock)
	zones, err := s.ListHostedZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(zones))
	}
	if zones[0].ID != "Z111" {
		t.Errorf("expected Z111, got %s", zones[0].ID)
	}
	if zones[0].Name != "example.com" {
		t.Errorf("expected example.com, got %s", zones[0].Name)
	}
	if zones[0].Count != 10 {
		t.Errorf("expected count 10, got %d", zones[0].Count)
	}
}

func TestListHostedZones_Paginated(t *testing.T) {
	mock := &mockRoute53{
		listZonesPages: []*route53.ListHostedZonesOutput{
			{
				HostedZones: []r53types.HostedZone{
					{Id: aws.String("/hostedzone/Z111"), Name: aws.String("page1.com."), ResourceRecordSetCount: aws.Int64(1)},
				},
				IsTruncated: true,
				NextMarker:  aws.String("marker1"),
			},
			{
				HostedZones: []r53types.HostedZone{
					{Id: aws.String("/hostedzone/Z222"), Name: aws.String("page2.com."), ResourceRecordSetCount: aws.Int64(2)},
				},
				IsTruncated: false,
			},
		},
	}
	s := NewScanner(mock)
	zones, err := s.ListHostedZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 2 {
		t.Fatalf("expected 2 zones across pages, got %d", len(zones))
	}
	if zones[1].Name != "page2.com" {
		t.Errorf("expected page2.com, got %s", zones[1].Name)
	}
}

func TestListHostedZones_Empty(t *testing.T) {
	mock := &mockRoute53{
		listZonesPages: []*route53.ListHostedZonesOutput{
			{HostedZones: []r53types.HostedZone{}, IsTruncated: false},
		},
	}
	s := NewScanner(mock)
	zones, err := s.ListHostedZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 0 {
		t.Errorf("expected 0 zones, got %d", len(zones))
	}
}

func TestListRecords(t *testing.T) {
	mock := &mockRoute53{
		listRecordPages: []*route53.ListResourceRecordSetsOutput{
			{
				ResourceRecordSets: []r53types.ResourceRecordSet{
					{
						Name: aws.String("example.com."),
						Type: r53types.RRTypeA,
						TTL:  aws.Int64(300),
						ResourceRecords: []r53types.ResourceRecord{
							{Value: aws.String("93.184.216.34")},
						},
					},
					{
						Name: aws.String("example.com."),
						Type: r53types.RRTypeAaaa,
						TTL:  aws.Int64(300),
						ResourceRecords: []r53types.ResourceRecord{
							{Value: aws.String("2606:2800:220:1:248:1893:25c8:1946")},
						},
					},
					{
						Name: aws.String("app.example.com."),
						Type: r53types.RRTypeCname,
						TTL:  aws.Int64(600),
						ResourceRecords: []r53types.ResourceRecord{
							{Value: aws.String("myapp.herokuapp.com")},
						},
					},
					{
						Name: aws.String("example.com."),
						Type: r53types.RRTypeMx,
						TTL:  aws.Int64(3600),
						ResourceRecords: []r53types.ResourceRecord{
							{Value: aws.String("10 mail.example.com")},
						},
					},
					{
						Name: aws.String("example.com."),
						Type: r53types.RRTypeNs,
						TTL:  aws.Int64(86400),
						ResourceRecords: []r53types.ResourceRecord{
							{Value: aws.String("ns1.example.com")},
						},
					},
					{
						Name: aws.String("example.com."),
						Type: r53types.RRTypeTxt,
						TTL:  aws.Int64(300),
						ResourceRecords: []r53types.ResourceRecord{
							{Value: aws.String("\"v=spf1 include:_spf.google.com ~all\"")},
						},
					},
					{
						Name: aws.String("example.com."),
						Type: r53types.RRTypeCaa,
						TTL:  aws.Int64(300),
						ResourceRecords: []r53types.ResourceRecord{
							{Value: aws.String("0 issue \"letsencrypt.org\"")},
						},
					},
				},
			},
		},
	}
	s := NewScanner(mock)
	records, err := s.ListRecords(context.Background(), "Z111")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 7 {
		t.Fatalf("expected 7 records, got %d", len(records))
	}

	// Verify A record
	if records[0].Type != "A" || records[0].Values[0] != "93.184.216.34" {
		t.Errorf("unexpected A record: %+v", records[0])
	}
	// Verify CNAME
	if records[2].Type != "CNAME" || records[2].Values[0] != "myapp.herokuapp.com" {
		t.Errorf("unexpected CNAME record: %+v", records[2])
	}
	// Verify name has trailing dot stripped
	if records[0].Name != "example.com" {
		t.Errorf("expected trailing dot stripped, got %s", records[0].Name)
	}
}

func TestListRecords_Paginated(t *testing.T) {
	mock := &mockRoute53{
		listRecordPages: []*route53.ListResourceRecordSetsOutput{
			{
				ResourceRecordSets: []r53types.ResourceRecordSet{
					{
						Name:            aws.String("a.example.com."),
						Type:            r53types.RRTypeA,
						TTL:             aws.Int64(300),
						ResourceRecords: []r53types.ResourceRecord{{Value: aws.String("1.2.3.4")}},
					},
				},
				IsTruncated:    true,
				NextRecordName: aws.String("b.example.com."),
				NextRecordType: r53types.RRTypeA,
			},
			{
				ResourceRecordSets: []r53types.ResourceRecordSet{
					{
						Name:            aws.String("b.example.com."),
						Type:            r53types.RRTypeA,
						TTL:             aws.Int64(300),
						ResourceRecords: []r53types.ResourceRecord{{Value: aws.String("5.6.7.8")}},
					},
				},
			},
		},
	}
	s := NewScanner(mock)
	records, err := s.ListRecords(context.Background(), "Z111")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records across pages, got %d", len(records))
	}
	if records[1].Values[0] != "5.6.7.8" {
		t.Errorf("expected 5.6.7.8 from page 2, got %s", records[1].Values[0])
	}
}

func TestListRecords_AliasRecord(t *testing.T) {
	mock := &mockRoute53{
		listRecordPages: []*route53.ListResourceRecordSetsOutput{
			{
				ResourceRecordSets: []r53types.ResourceRecordSet{
					{
						Name: aws.String("cdn.example.com."),
						Type: r53types.RRTypeA,
						AliasTarget: &r53types.AliasTarget{
							DNSName:              aws.String("d123.cloudfront.net."),
							HostedZoneId:         aws.String("Z2FDTNDATAQYW2"),
							EvaluateTargetHealth: false,
						},
					},
				},
			},
		},
	}
	s := NewScanner(mock)
	records, err := s.ListRecords(context.Background(), "Z111")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Values[0] != "d123.cloudfront.net" {
		t.Errorf("expected alias DNS name, got %s", records[0].Values[0])
	}
	if records[0].TTL != 0 {
		t.Errorf("expected 0 TTL for alias, got %d", records[0].TTL)
	}
}

func TestListRecords_FiltersUnsupported(t *testing.T) {
	mock := &mockRoute53{
		listRecordPages: []*route53.ListResourceRecordSetsOutput{
			{
				ResourceRecordSets: []r53types.ResourceRecordSet{
					{
						Name:            aws.String("example.com."),
						Type:            r53types.RRTypeSoa,
						TTL:             aws.Int64(900),
						ResourceRecords: []r53types.ResourceRecord{{Value: aws.String("ns1.example.com. admin.example.com. 1 3600 900 1209600 86400")}},
					},
					{
						Name:            aws.String("_sip.example.com."),
						Type:            r53types.RRTypeSrv,
						TTL:             aws.Int64(300),
						ResourceRecords: []r53types.ResourceRecord{{Value: aws.String("10 60 5060 sip.example.com")}},
					},
					{
						Name:            aws.String("example.com."),
						Type:            r53types.RRTypeA,
						TTL:             aws.Int64(300),
						ResourceRecords: []r53types.ResourceRecord{{Value: aws.String("1.2.3.4")}},
					},
				},
			},
		},
	}
	s := NewScanner(mock)
	records, err := s.ListRecords(context.Background(), "Z111")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record (SOA and SRV filtered), got %d", len(records))
	}
	if records[0].Type != "A" {
		t.Errorf("expected A record, got %s", records[0].Type)
	}
}

func TestNewScanner(t *testing.T) {
	s := NewScanner(&mockRoute53{})
	if s == nil {
		t.Fatal("NewScanner returned nil")
	}
}
