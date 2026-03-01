package commands

import (
	"bytes"
	"strings"
	"testing"
)

func TestScanRequiresMode(t *testing.T) {
	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)
	rootCmd.SetArgs([]string{"scan"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when neither --domain nor --platform is set")
	}
	if !strings.Contains(err.Error(), "either --domain or --platform must be specified") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestScanMutuallyExclusive(t *testing.T) {
	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)
	rootCmd.SetArgs([]string{"scan", "--domain", "example.com", "--platform", "aws", "--zone", "Z123"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when both --domain and --platform are set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestScanPlatformRequiresZone(t *testing.T) {
	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)
	rootCmd.SetArgs([]string{"scan", "--platform", "aws"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when --platform is set without --zone")
	}
	if !strings.Contains(err.Error(), "--zone is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestScanZoneRequiresPlatform(t *testing.T) {
	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)
	rootCmd.SetArgs([]string{"scan", "--zone", "Z123"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when --zone is set without --platform")
	}
	if !strings.Contains(err.Error(), "--zone requires --platform") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestScanDomainModeStub(t *testing.T) {
	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"scan", "--domain", "example.com"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "not implemented yet") {
		t.Errorf("expected stub message, got: %q", buf.String())
	}
}

func TestScanPlatformModeStub(t *testing.T) {
	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"scan", "--platform", "aws", "--zone", "Z123"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "not implemented yet") {
		t.Errorf("expected stub message, got: %q", buf.String())
	}
}

func TestScanInvalidPlatform(t *testing.T) {
	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)
	rootCmd.SetArgs([]string{"scan", "--platform", "digitalocean", "--zone", "Z123"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid platform")
	}
	if !strings.Contains(err.Error(), "unsupported platform") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestScanHelp(t *testing.T) {
	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"scan", "--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	for _, flag := range []string{"--platform", "--domain", "--zone", "--format", "--timeout", "--fingerprints"} {
		if !strings.Contains(output, flag) {
			t.Errorf("scan --help missing flag %s in output", flag)
		}
	}
}
