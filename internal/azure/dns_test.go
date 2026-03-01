package azure

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
)

func ptr[T any](v T) *T { return &v }

type mockAzureDNS struct {
	zones      []armdns.Zone
	recordSets []armdns.RecordSet
}

func (m *mockAzureDNS) ListZones(_ context.Context) ([]armdns.Zone, error) {
	return m.zones, nil
}

func (m *mockAzureDNS) ListRecordSets(_ context.Context, _, _ string) ([]armdns.RecordSet, error) {
	return m.recordSets, nil
}

func TestListZones(t *testing.T) {
	mock := &mockAzureDNS{
		zones: []armdns.Zone{
			{
				Name: ptr("example.com"),
				ID:   ptr("/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/dnszones/example.com"),
			},
			{
				Name: ptr("other.com"),
				ID:   ptr("/subscriptions/sub1/resourceGroups/rg2/providers/Microsoft.Network/dnszones/other.com"),
			},
		},
	}
	s := NewScanner(mock)
	zones, err := s.ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(zones))
	}
	if zones[0].Name != "example.com" {
		t.Errorf("expected example.com, got %s", zones[0].Name)
	}
	if zones[0].ResourceGroup != "rg1" {
		t.Errorf("expected rg1, got %s", zones[0].ResourceGroup)
	}
}

func TestListZones_Empty(t *testing.T) {
	mock := &mockAzureDNS{}
	s := NewScanner(mock)
	zones, err := s.ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 0 {
		t.Errorf("expected 0 zones, got %d", len(zones))
	}
}

func TestListRecords(t *testing.T) {
	mock := &mockAzureDNS{
		recordSets: []armdns.RecordSet{
			{
				Name: ptr("@"),
				Type: ptr("Microsoft.Network/dnszones/A"),
				Properties: &armdns.RecordSetProperties{
					TTL:      ptr[int64](300),
					ARecords: []*armdns.ARecord{{IPv4Address: ptr("93.184.216.34")}},
				},
			},
			{
				Name: ptr("@"),
				Type: ptr("Microsoft.Network/dnszones/AAAA"),
				Properties: &armdns.RecordSetProperties{
					TTL:         ptr[int64](300),
					AaaaRecords: []*armdns.AaaaRecord{{IPv6Address: ptr("2606:2800:220:1:248:1893:25c8:1946")}},
				},
			},
			{
				Name: ptr("app"),
				Type: ptr("Microsoft.Network/dnszones/CNAME"),
				Properties: &armdns.RecordSetProperties{
					TTL:         ptr[int64](600),
					CnameRecord: &armdns.CnameRecord{Cname: ptr("myapp.herokuapp.com")},
				},
			},
			{
				Name: ptr("@"),
				Type: ptr("Microsoft.Network/dnszones/MX"),
				Properties: &armdns.RecordSetProperties{
					TTL:       ptr[int64](3600),
					MxRecords: []*armdns.MxRecord{{Preference: ptr[int32](10), Exchange: ptr("mail.example.com")}},
				},
			},
			{
				Name: ptr("@"),
				Type: ptr("Microsoft.Network/dnszones/NS"),
				Properties: &armdns.RecordSetProperties{
					TTL:       ptr[int64](86400),
					NsRecords: []*armdns.NsRecord{{Nsdname: ptr("ns1.example.com")}},
				},
			},
			{
				Name: ptr("@"),
				Type: ptr("Microsoft.Network/dnszones/TXT"),
				Properties: &armdns.RecordSetProperties{
					TTL:        ptr[int64](300),
					TxtRecords: []*armdns.TxtRecord{{Value: []*string{ptr("v=spf1 include:_spf.google.com ~all")}}},
				},
			},
			{
				Name: ptr("@"),
				Type: ptr("Microsoft.Network/dnszones/CAA"),
				Properties: &armdns.RecordSetProperties{
					TTL:        ptr[int64](300),
					CaaRecords: []*armdns.CaaRecord{{Flags: ptr[int32](0), Tag: ptr("issue"), Value: ptr("letsencrypt.org")}},
				},
			},
		},
	}
	s := NewScanner(mock)
	records, err := s.ListRecords(context.Background(), "rg1", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 7 {
		t.Fatalf("expected 7 records, got %d", len(records))
	}
	// A record
	if records[0].Type != "A" || records[0].Values[0] != "93.184.216.34" {
		t.Errorf("unexpected A record: %+v", records[0])
	}
	// CNAME
	if records[2].Type != "CNAME" || records[2].Values[0] != "myapp.herokuapp.com" {
		t.Errorf("unexpected CNAME record: %+v", records[2])
	}
	// MX
	if records[3].Type != "MX" || records[3].Values[0] != "10 mail.example.com" {
		t.Errorf("unexpected MX record: %+v", records[3])
	}
	// CAA
	if records[6].Type != "CAA" || records[6].Values[0] != "0 issue letsencrypt.org" {
		t.Errorf("unexpected CAA record: %+v", records[6])
	}
}

func TestListRecords_FiltersUnsupported(t *testing.T) {
	mock := &mockAzureDNS{
		recordSets: []armdns.RecordSet{
			{
				Name:       ptr("@"),
				Type:       ptr("Microsoft.Network/dnszones/SOA"),
				Properties: &armdns.RecordSetProperties{TTL: ptr[int64](900)},
			},
			{
				Name: ptr("@"),
				Type: ptr("Microsoft.Network/dnszones/A"),
				Properties: &armdns.RecordSetProperties{
					TTL:      ptr[int64](300),
					ARecords: []*armdns.ARecord{{IPv4Address: ptr("1.2.3.4")}},
				},
			},
		},
	}
	s := NewScanner(mock)
	records, err := s.ListRecords(context.Background(), "rg1", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record (SOA filtered), got %d", len(records))
	}
	if records[0].Type != "A" {
		t.Errorf("expected A record, got %s", records[0].Type)
	}
}

func TestNewScanner(t *testing.T) {
	s := NewScanner(&mockAzureDNS{})
	if s == nil {
		t.Fatal("NewScanner returned nil")
	}
}

func TestExtractResourceGroup(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/dnszones/example.com", "rg1"},
		{"/subscriptions/sub1/resourceGroups/MyRG/providers/Microsoft.Network/dnszones/test.com", "MyRG"},
		{"", ""},
		{"/no/match/here", ""},
	}
	for _, tt := range tests {
		got := extractResourceGroup(tt.id)
		if got != tt.want {
			t.Errorf("extractResourceGroup(%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestExtractRecordType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Microsoft.Network/dnszones/A", "A"},
		{"Microsoft.Network/dnszones/CNAME", "CNAME"},
		{"A", "A"},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractRecordType(tt.input)
		if got != tt.want {
			t.Errorf("extractRecordType(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
