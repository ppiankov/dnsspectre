package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscover_ExplicitPath(t *testing.T) {
	// Explicit path always wins, even if env and XDG exist
	_ = os.Setenv("DNSSPECTRE_CONFIG", "/env/config.yaml")
	defer func() { _ = os.Unsetenv("DNSSPECTRE_CONFIG") }()

	got := Discover("/explicit/config.yaml")
	if got != "/explicit/config.yaml" {
		t.Errorf("Discover(explicit) = %q, want %q", got, "/explicit/config.yaml")
	}
}

func TestDiscover_EnvVar(t *testing.T) {
	// Env var wins when no explicit path
	_ = os.Setenv("DNSSPECTRE_CONFIG", "/env/config.yaml")
	defer func() { _ = os.Unsetenv("DNSSPECTRE_CONFIG") }()

	got := Discover("")
	if got != "/env/config.yaml" {
		t.Errorf("Discover(env) = %q, want %q", got, "/env/config.yaml")
	}
}

func TestDiscover_XDG(t *testing.T) {
	// XDG/platform-specific config dir wins when no explicit or env
	// Note: os.UserConfigDir() behavior is platform-dependent:
	// - Linux: $XDG_CONFIG_HOME or ~/.config
	// - macOS: ~/Library/Application Support
	// - Windows: %AppData%
	// We test by checking if the discovered path matches UserConfigDir() + /dnsspectre/config.yaml
	_ = os.Unsetenv("DNSSPECTRE_CONFIG")

	configHome, err := os.UserConfigDir()
	if err != nil {
		t.Skip("UserConfigDir not available")
	}

	xdgDir := filepath.Join(configHome, "dnsspectre")
	if err := os.MkdirAll(xdgDir, 0755); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(xdgDir) }() // cleanup

	xdgPath := filepath.Join(xdgDir, "config.yaml")
	if err := os.WriteFile(xdgPath, []byte("platform: aws"), 0644); err != nil {
		t.Fatal(err)
	}

	got := Discover("")
	if got != xdgPath {
		t.Errorf("Discover(xdg) = %q, want %q", got, xdgPath)
	}
}

func TestDiscover_NoConfig(t *testing.T) {
	// No explicit, no env, no XDG → empty string
	_ = os.Unsetenv("DNSSPECTRE_CONFIG")
	_ = os.Setenv("XDG_CONFIG_HOME", "/nonexistent")
	defer func() { _ = os.Unsetenv("XDG_CONFIG_HOME") }()

	got := Discover("")
	if got != "" {
		t.Errorf("Discover(none) = %q, want empty", got)
	}
}

func TestDiscover_NoCWFallback(t *testing.T) {
	// CWD .dnsspectre.yaml should NOT be discovered (no CWD fallback)
	_ = os.Unsetenv("DNSSPECTRE_CONFIG")
	_ = os.Setenv("XDG_CONFIG_HOME", "/nonexistent")
	defer func() { _ = os.Unsetenv("XDG_CONFIG_HOME") }()

	// Create CWD config (should be ignored)
	tmpDir := t.TempDir()
	cwdConfig := filepath.Join(tmpDir, ".dnsspectre.yaml")
	if err := os.WriteFile(cwdConfig, []byte("platform: aws"), 0644); err != nil {
		t.Fatal(err)
	}

	// Change to tmpDir
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	got := Discover("")
	if got != "" {
		t.Errorf("Discover(no-cwd-fallback) = %q, want empty", got)
	}
}
