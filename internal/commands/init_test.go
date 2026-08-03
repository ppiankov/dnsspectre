package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// WO-24: Tests for init command config file creation

func TestInitCreatesConfigFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"init", "--path", configPath})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	configPath := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(configPath, []byte("existing"), 0644); err != nil {
		t.Fatal(err)
	}

	vi := VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
	rootCmd, _ := NewRootCmd(vi)
	rootCmd.SetArgs([]string{"init", "--path", configPath})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when config already exists")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("unexpected error: %v", err)
	}
}
