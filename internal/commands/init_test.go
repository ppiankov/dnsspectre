package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitCreatesConfigFile(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"init"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	configPath := filepath.Join(dir, ".dnsspectre.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("config file not created: %v", err)
	}

	content := string(data)
	for _, keyword := range []string{"platform", "format", "timeout", "fingerprints", "zone", "domain"} {
		if !strings.Contains(content, keyword) {
			t.Errorf("config missing keyword %q", keyword)
		}
	}

	if !strings.Contains(buf.String(), "created") {
		t.Errorf("expected 'created' message, got: %q", buf.String())
	}
}

func TestInitRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, ".dnsspectre.yaml"), []byte("existing"), 0644); err != nil {
		t.Fatal(err)
	}

	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)
	rootCmd.SetArgs([]string{"init"})

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when config already exists")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("unexpected error: %v", err)
	}
}
