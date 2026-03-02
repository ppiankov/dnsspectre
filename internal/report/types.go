package report

import (
	"github.com/ppiankov/dnsspectre/internal/analyzer"
)

// Report is the spectre/v1 JSON envelope.
type Report struct {
	Schema   string          `json:"schema"`
	Target   ReportTarget    `json:"target"`
	Findings []ReportFinding `json:"findings"`
	Summary  ReportSummary   `json:"summary"`
}

// ReportTarget identifies what was scanned.
type ReportTarget struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

// ReportFinding is a single finding in the report.
type ReportFinding struct {
	Type     string          `json:"type"`
	Severity string          `json:"severity"`
	Domain   string          `json:"domain"`
	Target   string          `json:"target,omitempty"`
	Service  string          `json:"service,omitempty"`
	Detail   string          `json:"detail"`
	Metadata FindingMetadata `json:"metadata"`
}

// FindingMetadata contains the source DNS record details.
type FindingMetadata struct {
	RecordName   string   `json:"record_name"`
	RecordType   string   `json:"record_type"`
	RecordValues []string `json:"record_values"`
	RecordTTL    int64    `json:"record_ttl"`
}

// ReportSummary counts findings by severity.
type ReportSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

func buildReport(zoneName string, findings []analyzer.Finding) Report {
	report := Report{
		Schema: "spectre/v1",
		Target: ReportTarget{
			Type: "dns-zone",
			Name: zoneName,
		},
		Findings: make([]ReportFinding, 0, len(findings)),
	}

	for _, f := range findings {
		rf := ReportFinding{
			Type:     string(f.Type),
			Severity: string(f.Severity),
			Domain:   f.Domain,
			Target:   f.Target,
			Service:  f.Service,
			Detail:   f.Detail,
			Metadata: FindingMetadata{
				RecordName:   f.Record.Name,
				RecordType:   f.Record.Type,
				RecordValues: f.Record.Values,
				RecordTTL:    f.Record.TTL,
			},
		}
		if rf.Metadata.RecordValues == nil {
			rf.Metadata.RecordValues = []string{}
		}
		report.Findings = append(report.Findings, rf)

		switch analyzer.Severity(rf.Severity) {
		case analyzer.SeverityCritical:
			report.Summary.Critical++
		case analyzer.SeverityHigh:
			report.Summary.High++
		case analyzer.SeverityMedium:
			report.Summary.Medium++
		case analyzer.SeverityLow:
			report.Summary.Low++
		case analyzer.SeverityInfo:
			report.Summary.Info++
		}
	}
	report.Summary.Total = len(findings)

	return report
}
