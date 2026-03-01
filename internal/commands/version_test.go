package commands

import (
	"bytes"
	"testing"
)

func TestVersionCmd(t *testing.T) {
	vi := VersionInfo{Version: "1.2.3", Commit: "abc1234", Date: "2025-01-01T00:00:00Z"}
	rootCmd, _ := NewRootCmd(vi)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"version"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "dnsspectre 1.2.3 (commit: abc1234, built: 2025-01-01T00:00:00Z)\n"
	if got := buf.String(); got != want {
		t.Errorf("version output = %q, want %q", got, want)
	}
}

func TestVersionCmdDevDefaults(t *testing.T) {
	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"version"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "dnsspectre dev (commit: none, built: unknown)\n"
	if got := buf.String(); got != want {
		t.Errorf("version output = %q, want %q", got, want)
	}
}
