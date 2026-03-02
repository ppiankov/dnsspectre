package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ppiankov/dnsspectre/internal/analyzer"
)

var severityOrder = map[analyzer.Severity]int{
	analyzer.SeverityCritical: 0,
	analyzer.SeverityHigh:     1,
	analyzer.SeverityMedium:   2,
	analyzer.SeverityLow:      3,
	analyzer.SeverityInfo:     4,
}

// WriteText writes findings as a human-readable text report.
func WriteText(w io.Writer, zoneName string, findings []analyzer.Finding) error {
	header := fmt.Sprintf("dnsspectre report for %s", zoneName)
	if _, err := fmt.Fprintln(w, header); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, strings.Repeat("=", len(header))); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	sorted := make([]analyzer.Finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		return severityOrder[sorted[i].Severity] < severityOrder[sorted[j].Severity]
	})

	for _, f := range sorted {
		if _, err := fmt.Fprintf(w, "%-10s%-25s%s\n", f.Severity, f.Type, f.Domain); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "          %s\n\n", f.Detail); err != nil {
			return err
		}
	}

	report := buildReport(zoneName, findings)
	var parts []string
	if report.Summary.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", report.Summary.Critical))
	}
	if report.Summary.High > 0 {
		parts = append(parts, fmt.Sprintf("%d high", report.Summary.High))
	}
	if report.Summary.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", report.Summary.Medium))
	}
	if report.Summary.Low > 0 {
		parts = append(parts, fmt.Sprintf("%d low", report.Summary.Low))
	}
	if report.Summary.Info > 0 {
		parts = append(parts, fmt.Sprintf("%d info", report.Summary.Info))
	}

	if len(parts) > 0 {
		if _, err := fmt.Fprintf(w, "Summary: %d findings (%s)\n", report.Summary.Total, strings.Join(parts, ", ")); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(w, "Summary: 0 findings"); err != nil {
			return err
		}
	}
	return nil
}
