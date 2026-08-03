package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const configFileName = "config.yaml"

const sampleConfig = `# dnsspectre configuration
# See: https://github.com/ppiankov/dnsspectre

# Cloud platform for DNS record enumeration.
# Supported: aws, gcp, azure, cloudflare
# Leave empty to use direct DNS queries with --domain.
# platform: aws

# Zone ID for platform mode.
# Required when platform is set.
# zone: Z0123456789ABCDEF

# Domain for DNS query mode.
# Used when platform is not set.
# domain: example.com

# Output format: json, text, sarif, spectrehub
format: text

# DNS resolution timeout.
timeout: 5s

# Path to custom fingerprints file.
# Defaults to built-in fingerprints if not specified.
# fingerprints: /path/to/fingerprints.yaml
`

// WO-24: newInitCmd creates the init command with --path flag for config location override.
func newInitCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a sample configuration file",
		Long: `Generate a sample dnsspectre configuration file.

By default, creates the config in the platform-specific config directory:
  Linux:   ~/.config/dnsspectre/config.yaml
  macOS:   ~/Library/Application Support/dnsspectre/config.yaml
  Windows: %AppData%\dnsspectre\config.yaml

Use --path to override (e.g., --path .dnsspectre.yaml for project-local config).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit(cmd, configPath)
		},
	}

	cmd.Flags().StringVar(&configPath, "path", "", "config file path (default: platform-specific config dir)")
	return cmd
}

// WO-24: runInit creates a sample config file in platform-specific dir or --path override.
func runInit(cmd *cobra.Command, configPath string) error {
	dest := configPath

	// If no --path provided, use platform-specific config dir
	if dest == "" {
		configHome, err := os.UserConfigDir()
		if err != nil {
			return fmt.Errorf("cannot determine config directory: %w", err)
		}
		dest = filepath.Join(configHome, "dnsspectre", configFileName)
	}

	// Create parent directories if needed
	if dir := filepath.Dir(dest); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating config directory: %w", err)
		}
	}

	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("%s already exists; remove it first or edit it directly", dest)
	}

	if err := os.WriteFile(dest, []byte(sampleConfig), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", dest, err)
	}

	_, err := fmt.Fprintf(cmd.OutOrStdout(), "created %s\n", dest)
	return err
}
