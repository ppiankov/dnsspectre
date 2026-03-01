package commands

import (
	"strings"
	"testing"
)

func TestRootCmdInvalidFormat(t *testing.T) {
	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)
	rootCmd.SetArgs([]string{"scan", "--domain", "example.com", "--format", "csv"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("unexpected error: %v", err)
	}
}
