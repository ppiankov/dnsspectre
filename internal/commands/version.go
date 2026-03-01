package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCmd(vi VersionInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, and build date",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "dnsspectre %s (commit: %s, built: %s)\n",
				vi.Version, vi.Commit, vi.Date)
			return err
		},
	}
}
