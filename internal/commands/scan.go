package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newScanCmd(opts *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Scan DNS records for dangling entries and takeover risks",
		Long: `Scan DNS records for dangling CNAME entries and other misconfigurations
that could lead to subdomain takeover.

Requires either --domain (DNS query mode) or --platform with --zone
(platform enumeration mode).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateScanFlags(opts); err != nil {
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "scan: not implemented yet")
			return err
		},
	}
}

func validateScanFlags(opts *GlobalOptions) error {
	hasPlatform := opts.Platform != ""
	hasDomain := opts.Domain != ""
	hasZone := opts.Zone != ""

	if !hasPlatform && hasZone {
		return fmt.Errorf("--zone requires --platform")
	}
	if !hasPlatform && !hasDomain {
		return fmt.Errorf("either --domain or --platform must be specified")
	}
	if hasPlatform && hasDomain {
		return fmt.Errorf("--domain and --platform are mutually exclusive")
	}
	if hasPlatform && !hasZone {
		return fmt.Errorf("--zone is required when using --platform")
	}
	return nil
}
