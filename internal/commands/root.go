package commands

import (
	"time"

	"github.com/spf13/cobra"
)

// NewRootCmd creates the root command with all global persistent flags.
func NewRootCmd(vi VersionInfo) (*cobra.Command, *GlobalOptions) {
	opts := &GlobalOptions{}

	rootCmd := &cobra.Command{
		Use:   "dnsspectre",
		Short: "DNS hygiene and subdomain takeover detection",
		Long: `dnsspectre scans DNS records for dangling CNAME entries and other
misconfigurations that could lead to subdomain takeover.

It supports direct DNS queries or platform-specific enumeration via
AWS Route53, GCP Cloud DNS, Azure DNS, or Cloudflare.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if err := ValidatePlatform(opts.Platform); err != nil {
				return err
			}
			return ValidateFormat(opts.Format)
		},
	}

	f := rootCmd.PersistentFlags()
	f.StringVar(&opts.Platform, "platform", "", "cloud platform: aws, gcp, azure, cloudflare")
	f.StringVar(&opts.Domain, "domain", "", "domain for DNS query mode")
	f.StringVar(&opts.Zone, "zone", "", "zone ID for platform mode")
	f.StringVar(&opts.Format, "format", "text", "output format: json, text, sarif, spectrehub")
	f.DurationVar(&opts.Timeout, "timeout", 5*time.Second, "DNS resolution timeout")
	f.StringVar(&opts.Fingerprints, "fingerprints", "", "path to custom fingerprints file")

	rootCmd.AddCommand(newVersionCmd(vi))
	rootCmd.AddCommand(newScanCmd(opts))
	rootCmd.AddCommand(newInitCmd())

	return rootCmd, opts
}

// Execute is the entry point called from main.
func Execute(vi VersionInfo) error {
	rootCmd, _ := NewRootCmd(vi)
	return rootCmd.Execute()
}
