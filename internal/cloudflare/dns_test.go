package cloudflare

import (
	"context"
	"testing"

	cfdns "github.com/cloudflare/cloudflare-go/v4/dns"
	cfzones "github.com/cloudflare/cloudflare-go/v4/zones"
)

type mockCloudflare struct {
	zones   []cfzones.Zone
	records []cfdns.RecordResponse
}

func (m *mockCloudflare) ListZones(_ context.Context) ([]cfzones.Zone, error) {
	return m.zones, nil
}

func (m *mockCloudflare) ListDNSRecords(_ context.Context, _ string) ([]cfdns.RecordResponse, error) {
	return m.records, nil
}

func TestListZones(t *testing.T) {
	mock := &mockCloudflare{
		zones: []cfzones.Zone{
			{ID: "zone-1", Name: "example.com"},
			{ID: "zone-2", Name: "other.com"},
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
	if zones[0].ID != "zone-1" {
		t.Errorf("expected zone-1, got %s", zones[0].ID)
	}
	if zones[0].Name != "example.com" {
		t.Errorf("expected example.com, got %s", zones[0].Name)
	}
}

func TestListZones_Empty(t *testing.T) {
	mock := &mockCloudflare{}
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
	mock := &mockCloudflare{
		records: []cfdns.RecordResponse{
			{Name: "example.com", Type: cfdns.RecordResponseTypeA, Content: "93.184.216.34", TTL: 300},
			{Name: "example.com", Type: cfdns.RecordResponseTypeAAAA, Content: "2606:2800:220:1:248:1893:25c8:1946", TTL: 300},
			{Name: "app.example.com", Type: cfdns.RecordResponseTypeCNAME, Content: "myapp.herokuapp.com", TTL: 600},
			{Name: "example.com", Type: cfdns.RecordResponseTypeMX, Content: "mail.example.com", Priority: 10, TTL: 3600},
			{Name: "example.com", Type: cfdns.RecordResponseTypeNS, Content: "ns1.example.com", TTL: 86400},
			{Name: "example.com", Type: cfdns.RecordResponseTypeTXT, Content: "v=spf1 include:_spf.google.com ~all", TTL: 300},
			{Name: "example.com", Type: cfdns.RecordResponseTypeCAA, Content: "0 issue letsencrypt.org", TTL: 300},
		},
	}
	s := NewScanner(mock)
	records, err := s.ListRecords(context.Background(), "zone-1")
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
	mock := &mockCloudflare{
		records: []cfdns.RecordResponse{
			{Name: "example.com", Type: cfdns.RecordResponseTypeSRV, Content: "0 5 5060 sip.example.com", TTL: 300},
			{Name: "example.com", Type: cfdns.RecordResponseTypeA, Content: "1.2.3.4", TTL: 300},
		},
	}
	s := NewScanner(mock)
	records, err := s.ListRecords(context.Background(), "zone-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record (SRV filtered), got %d", len(records))
	}
	if records[0].Type != "A" {
		t.Errorf("expected A record, got %s", records[0].Type)
	}
}

func TestNewScanner(t *testing.T) {
	s := NewScanner(&mockCloudflare{})
	if s == nil {
		t.Fatal("NewScanner returned nil")
	}
}
