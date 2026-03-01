package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const configFileName = ".dnsspectre.yaml"

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

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Generate a sample .dnsspectre.yaml configuration file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit(cmd)
		},
	}
}

func runInit(cmd *cobra.Command) error {
	dest := filepath.Join(".", configFileName)

	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("%s already exists; remove it first or edit it directly", configFileName)
	}

	if err := os.WriteFile(dest, []byte(sampleConfig), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", configFileName, err)
	}

	_, err := fmt.Fprintf(cmd.OutOrStdout(), "created %s\n", dest)
	return err
}
