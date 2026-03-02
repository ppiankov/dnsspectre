package config

import (
	"errors"
	"io/fs"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds settings from .dnsspectre.yaml.
type Config struct {
	Platform     string           `yaml:"platform"`
	Domain       string           `yaml:"domain"`
	Zone         string           `yaml:"zone"`
	Format       string           `yaml:"format"`
	Timeout      string           `yaml:"timeout"`
	Fingerprints string           `yaml:"fingerprints"`
	GCP          GCPConfig        `yaml:"gcp"`
	Azure        AzureConfig      `yaml:"azure"`
	Cloudflare   CloudflareConfig `yaml:"cloudflare"`
}

// GCPConfig holds GCP-specific settings.
type GCPConfig struct {
	Project string `yaml:"project"`
}

// AzureConfig holds Azure-specific settings.
type AzureConfig struct {
	SubscriptionID string `yaml:"subscription_id"`
}

// CloudflareConfig holds Cloudflare-specific settings.
type CloudflareConfig struct {
	APIToken string `yaml:"api_token"`
}

// Load reads a config file. Returns an empty Config if the file does not exist.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &Config{}, nil
		}
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// GCPProject returns the GCP project, preferring env var over config.
func (c *Config) GCPProject() string {
	if v := os.Getenv("DNSSPECTRE_GCP_PROJECT"); v != "" {
		return v
	}
	return c.GCP.Project
}

// AzureSubscription returns the Azure subscription ID, preferring env var over config.
func (c *Config) AzureSubscription() string {
	if v := os.Getenv("DNSSPECTRE_AZURE_SUBSCRIPTION_ID"); v != "" {
		return v
	}
	return c.Azure.SubscriptionID
}

// CloudflareToken returns the Cloudflare API token, preferring env var over config.
func (c *Config) CloudflareToken() string {
	if v := os.Getenv("DNSSPECTRE_CLOUDFLARE_API_TOKEN"); v != "" {
		return v
	}
	return c.Cloudflare.APIToken
}
