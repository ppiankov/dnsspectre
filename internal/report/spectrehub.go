package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ppiankov/dnsspectre/internal/analyzer"
)

// WriteJSON writes findings as a spectre/v1 JSON envelope.
func WriteJSON(w io.Writer, zoneName string, findings []analyzer.Finding) error {
	report := buildReport(zoneName, findings)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	_, err = w.Write(data)
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	_, err = fmt.Fprintln(w)
	if err != nil {
		return fmt.Errorf("write newline: %w", err)
	}
	return nil
}
