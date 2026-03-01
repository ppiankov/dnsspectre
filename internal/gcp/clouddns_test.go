package gcp

import (
	"context"
	"testing"

	"google.golang.org/api/dns/v1"
)

type mockCloudDNS struct {
	zonesPages  []*dns.ManagedZonesListResponse
	zonesIndex  int
	recordPages []*dns.ResourceRecordSetsListResponse
	recordIndex int
}

func (m *mockCloudDNS) ListManagedZones(_ context.Context, _, _ string) (*dns.ManagedZonesListResponse, error) {
	if m.zonesIndex >= len(m.zonesPages) {
		return &dns.ManagedZonesListResponse{}, nil
	}
	out := m.zonesPages[m.zonesIndex]
	m.zonesIndex++
	return out, nil
}

func (m *mockCloudDNS) ListRecordSets(_ context.Context, _, _, _ string) (*dns.ResourceRecordSetsListResponse, error) {
	if m.recordIndex >= len(m.recordPages) {
		return &dns.ResourceRecordSetsListResponse{}, nil
	}
	out := m.recordPages[m.recordIndex]
	m.recordIndex++
	return out, nil
}

func TestListZones(t *testing.T) {
	mock := &mockCloudDNS{
		zonesPages: []*dns.ManagedZonesListResponse{
			{
				ManagedZones: []*dns.ManagedZone{
					{Name: "example-zone", DnsName: "example.com.", Description: "test zone"},
					{Name: "other-zone", DnsName: "other.com.", Description: ""},
				},
			},
		},
	}
	s := NewScanner(mock)
	zones, err := s.ListZones(context.Background(), "my-project")
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(zones))
	}
	if zones[0].Name != "example-zone" {
		t.Errorf("expected example-zone, got %s", zones[0].Name)
	}
	if zones[0].DNSName != "example.com" {
		t.Errorf("expected example.com (no trailing dot), got %s", zones[0].DNSName)
	}
}

func TestListZones_Paginated(t *testing.T) {
	mock := &mockCloudDNS{
		zonesPages: []*dns.ManagedZonesListResponse{
			{
				ManagedZones:  []*dns.ManagedZone{{Name: "zone1", DnsName: "z1.com."}},
				NextPageToken: "token1",
			},
			{
				ManagedZones: []*dns.ManagedZone{{Name: "zone2", DnsName: "z2.com."}},
			},
		},
	}
	s := NewScanner(mock)
	zones, err := s.ListZones(context.Background(), "my-project")
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 2 {
		t.Fatalf("expected 2 zones across pages, got %d", len(zones))
	}
	if zones[1].DNSName != "z2.com" {
		t.Errorf("expected z2.com, got %s", zones[1].DNSName)
	}
}

func TestListZones_Empty(t *testing.T) {
	mock := &mockCloudDNS{
		zonesPages: []*dns.ManagedZonesListResponse{{}},
	}
	s := NewScanner(mock)
	zones, err := s.ListZones(context.Background(), "my-project")
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 0 {
		t.Errorf("expected 0 zones, got %d", len(zones))
	}
}

func TestListRecords(t *testing.T) {
	mock := &mockCloudDNS{
		recordPages: []*dns.ResourceRecordSetsListResponse{
			{
				Rrsets: []*dns.ResourceRecordSet{
					{Name: "example.com.", Type: "A", Rrdatas: []string{"93.184.216.34"}, Ttl: 300},
					{Name: "example.com.", Type: "AAAA", Rrdatas: []string{"2606:2800:220:1:248:1893:25c8:1946"}, Ttl: 300},
					{Name: "app.example.com.", Type: "CNAME", Rrdatas: []string{"myapp.herokuapp.com."}, Ttl: 600},
					{Name: "example.com.", Type: "MX", Rrdatas: []string{"10 mail.example.com."}, Ttl: 3600},
					{Name: "example.com.", Type: "NS", Rrdatas: []string{"ns1.example.com."}, Ttl: 86400},
					{Name: "example.com.", Type: "TXT", Rrdatas: []string{"v=spf1 include:_spf.google.com ~all"}, Ttl: 300},
					{Name: "example.com.", Type: "CAA", Rrdatas: []string{"0 issue letsencrypt.org"}, Ttl: 300},
				},
			},
		},
	}
	s := NewScanner(mock)
	records, err := s.ListRecords(context.Background(), "my-project", "example-zone")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 7 {
		t.Fatalf("expected 7 records, got %d", len(records))
	}
	if records[0].Type != "A" || records[0].Values[0] != "93.184.216.34" {
		t.Errorf("unexpected A record: %+v", records[0])
	}
	if records[0].Name != "example.com" {
		t.Errorf("expected trailing dot stripped, got %s", records[0].Name)
	}
}

func TestListRecords_FiltersUnsupported(t *testing.T) {
	mock := &mockCloudDNS{
		recordPages: []*dns.ResourceRecordSetsListResponse{
			{
				Rrsets: []*dns.ResourceRecordSet{
					{Name: "example.com.", Type: "SOA", Rrdatas: []string{"ns1.example.com. admin.example.com. 1 3600 900 1209600 86400"}, Ttl: 900},
					{Name: "example.com.", Type: "A", Rrdatas: []string{"1.2.3.4"}, Ttl: 300},
				},
			},
		},
	}
	s := NewScanner(mock)
	records, err := s.ListRecords(context.Background(), "my-project", "example-zone")
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
	s := NewScanner(&mockCloudDNS{})
	if s == nil {
		t.Fatal("NewScanner returned nil")
	}
}
