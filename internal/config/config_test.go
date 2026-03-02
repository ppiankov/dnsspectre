package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".dnsspectre.yaml")

	data := []byte(`platform: aws
domain: example.com
zone: Z123
format: json
timeout: 10s
gcp:
  project: my-project
azure:
  subscription_id: sub-123
cloudflare:
  api_token: tok-abc
`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Platform != "aws" {
		t.Errorf("Platform = %q, want %q", cfg.Platform, "aws")
	}
	if cfg.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", cfg.Domain, "example.com")
	}
	if cfg.Zone != "Z123" {
		t.Errorf("Zone = %q, want %q", cfg.Zone, "Z123")
	}
	if cfg.Format != "json" {
		t.Errorf("Format = %q, want %q", cfg.Format, "json")
	}
	if cfg.GCP.Project != "my-project" {
		t.Errorf("GCP.Project = %q, want %q", cfg.GCP.Project, "my-project")
	}
	if cfg.Azure.SubscriptionID != "sub-123" {
		t.Errorf("Azure.SubscriptionID = %q, want %q", cfg.Azure.SubscriptionID, "sub-123")
	}
	if cfg.Cloudflare.APIToken != "tok-abc" {
		t.Errorf("Cloudflare.APIToken = %q, want %q", cfg.Cloudflare.APIToken, "tok-abc")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Platform != "" {
		t.Errorf("expected empty Platform, got %q", cfg.Platform)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte(":\n  :\n    - [invalid"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestGCPProject_EnvOverride(t *testing.T) {
	cfg := &Config{GCP: GCPConfig{Project: "from-config"}}

	t.Setenv("DNSSPECTRE_GCP_PROJECT", "from-env")
	if got := cfg.GCPProject(); got != "from-env" {
		t.Errorf("GCPProject() = %q, want %q", got, "from-env")
	}
}

func TestGCPProject_FallbackToConfig(t *testing.T) {
	cfg := &Config{GCP: GCPConfig{Project: "from-config"}}

	t.Setenv("DNSSPECTRE_GCP_PROJECT", "")
	if got := cfg.GCPProject(); got != "from-config" {
		t.Errorf("GCPProject() = %q, want %q", got, "from-config")
	}
}

func TestAzureSubscription_EnvOverride(t *testing.T) {
	cfg := &Config{Azure: AzureConfig{SubscriptionID: "from-config"}}

	t.Setenv("DNSSPECTRE_AZURE_SUBSCRIPTION_ID", "from-env")
	if got := cfg.AzureSubscription(); got != "from-env" {
		t.Errorf("AzureSubscription() = %q, want %q", got, "from-env")
	}
}

func TestCloudflareToken_EnvOverride(t *testing.T) {
	cfg := &Config{Cloudflare: CloudflareConfig{APIToken: "from-config"}}

	t.Setenv("DNSSPECTRE_CLOUDFLARE_API_TOKEN", "from-env")
	if got := cfg.CloudflareToken(); got != "from-env" {
		t.Errorf("CloudflareToken() = %q, want %q", got, "from-env")
	}
}
