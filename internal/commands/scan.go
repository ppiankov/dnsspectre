package commands

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ppiankov/dnsspectre/internal/analyzer"
	"github.com/ppiankov/dnsspectre/internal/aws"
	"github.com/ppiankov/dnsspectre/internal/azure"
	"github.com/ppiankov/dnsspectre/internal/cloudflare"
	"github.com/ppiankov/dnsspectre/internal/config"
	"github.com/ppiankov/dnsspectre/internal/dns"
	"github.com/ppiankov/dnsspectre/internal/gcp"
	"github.com/ppiankov/dnsspectre/internal/report"
)

func newScanCmd(opts *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Scan DNS records for dangling entries and takeover risks",
		Long: `Scan DNS records for dangling CNAME entries and other misconfigurations
that could lead to subdomain takeover.

Requires either --domain (DNS query mode) or --platform
(platform enumeration mode). When using --platform, --zone is optional;
omit it to scan all zones.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateScanFlags(opts); err != nil {
				return err
			}
			ctx := cmd.Context()
			return runScan(ctx, opts, cmd.OutOrStdout(), nil)
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
	return nil
}

// runScan orchestrates: config → resolver → records → analyze → report.
// resolverOverride allows tests to inject a mock resolver.
func runScan(ctx context.Context, opts *GlobalOptions, w io.Writer, resolverOverride dns.Resolver) error {
	cfg, err := config.Load(".dnsspectre.yaml")
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	var resolver dns.Resolver
	if resolverOverride != nil {
		resolver = resolverOverride
	} else {
		r, err := dns.NewResolver(dns.WithTimeout(opts.Timeout))
		if err != nil {
			return fmt.Errorf("create resolver: %w", err)
		}
		resolver = r
	}

	fingerprints := dns.BuiltinFingerprints()

	var zoneName string
	var records []analyzer.Record

	if opts.Domain != "" {
		zoneName = opts.Domain
		records = dnsQueryRecords(ctx, resolver, opts.Domain)
	} else {
		zoneName, records, err = platformRecords(ctx, opts, cfg)
		if err != nil {
			return err
		}
	}

	a := analyzer.New(resolver, fingerprints)
	findings, err := a.Analyze(ctx, records)
	if err != nil {
		return fmt.Errorf("analyze: %w", err)
	}

	switch opts.Format {
	case "json", "spectrehub":
		return report.WriteJSON(w, zoneName, findings)
	default:
		return report.WriteText(w, zoneName, findings)
	}
}

// dnsQueryRecords queries CNAME, MX, NS, CAA for a single domain.
// Errors on individual record types are non-fatal.
func dnsQueryRecords(ctx context.Context, resolver dns.Resolver, domain string) []analyzer.Record {
	var records []analyzer.Record

	// CNAME
	if result, err := resolver.ResolveCNAME(ctx, domain); err == nil && result.CNAME != "" {
		records = append(records, analyzer.Record{
			Name:   domain,
			Type:   "CNAME",
			Values: []string{result.CNAME},
		})
	}

	// MX
	if result, err := resolver.ResolveMX(ctx, domain); err == nil && len(result.Hosts) > 0 {
		records = append(records, analyzer.Record{
			Name:   domain,
			Type:   "MX",
			Values: result.Hosts,
		})
	}

	// NS
	if result, err := resolver.ResolveNS(ctx, domain); err == nil && len(result.Hosts) > 0 {
		records = append(records, analyzer.Record{
			Name:   domain,
			Type:   "NS",
			Values: result.Hosts,
		})
	}

	// CAA
	if result, err := resolver.ResolveCAA(ctx, domain); err == nil && len(result.CAAs) > 0 {
		var values []string
		for _, caa := range result.CAAs {
			values = append(values, fmt.Sprintf("%d %s %s", caa.Flag, caa.Tag, caa.Value))
		}
		records = append(records, analyzer.Record{
			Name:   domain,
			Type:   "CAA",
			Values: values,
		})
	}

	return records
}

func platformRecords(ctx context.Context, opts *GlobalOptions, cfg *config.Config) (string, []analyzer.Record, error) {
	switch opts.Platform {
	case "aws":
		return awsRecords(ctx, opts)
	case "gcp":
		return gcpRecords(ctx, opts, cfg)
	case "azure":
		return azureRecords(ctx, opts, cfg)
	case "cloudflare":
		return cloudflareRecords(ctx, opts, cfg)
	default:
		return "", nil, fmt.Errorf("unsupported platform %q", opts.Platform)
	}
}

func awsRecords(ctx context.Context, opts *GlobalOptions) (string, []analyzer.Record, error) {
	scanner, err := aws.NewScannerFromConfig(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("create AWS scanner: %w", err)
	}

	if opts.Zone != "" {
		recs, err := scanner.ListRecords(ctx, opts.Zone)
		if err != nil {
			return "", nil, fmt.Errorf("list AWS records: %w", err)
		}
		return opts.Zone, convertAWSRecords(recs), nil
	}

	zones, err := scanner.ListHostedZones(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("list AWS zones: %w", err)
	}

	var all []analyzer.Record
	for _, z := range zones {
		recs, err := scanner.ListRecords(ctx, z.ID)
		if err != nil {
			return "", nil, fmt.Errorf("list AWS records for zone %s: %w", z.ID, err)
		}
		all = append(all, convertAWSRecords(recs)...)
	}
	return "aws", all, nil
}

func gcpRecords(ctx context.Context, opts *GlobalOptions, cfg *config.Config) (string, []analyzer.Record, error) {
	project := cfg.GCPProject()
	if project == "" {
		return "", nil, fmt.Errorf("GCP project required: set DNSSPECTRE_GCP_PROJECT or gcp.project in config")
	}

	scanner, err := gcp.NewScannerFromConfig(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("create GCP scanner: %w", err)
	}

	if opts.Zone != "" {
		recs, err := scanner.ListRecords(ctx, project, opts.Zone)
		if err != nil {
			return "", nil, fmt.Errorf("list GCP records: %w", err)
		}
		return opts.Zone, convertGCPRecords(recs), nil
	}

	zones, err := scanner.ListZones(ctx, project)
	if err != nil {
		return "", nil, fmt.Errorf("list GCP zones: %w", err)
	}

	var all []analyzer.Record
	for _, z := range zones {
		recs, err := scanner.ListRecords(ctx, project, z.Name)
		if err != nil {
			return "", nil, fmt.Errorf("list GCP records for zone %s: %w", z.Name, err)
		}
		all = append(all, convertGCPRecords(recs)...)
	}
	return "gcp", all, nil
}

func azureRecords(ctx context.Context, opts *GlobalOptions, cfg *config.Config) (string, []analyzer.Record, error) {
	subID := cfg.AzureSubscription()
	if subID == "" {
		return "", nil, fmt.Errorf("azure subscription ID required: set DNSSPECTRE_AZURE_SUBSCRIPTION_ID or azure.subscription_id in config")
	}

	scanner, err := azure.NewScannerFromConfig(ctx, subID)
	if err != nil {
		return "", nil, fmt.Errorf("create Azure scanner: %w", err)
	}

	if opts.Zone != "" {
		parts := strings.SplitN(opts.Zone, "/", 2)
		if len(parts) != 2 {
			return "", nil, fmt.Errorf("--zone must be in format resourceGroup/zoneName for azure")
		}
		recs, err := scanner.ListRecords(ctx, parts[0], parts[1])
		if err != nil {
			return "", nil, fmt.Errorf("list Azure records: %w", err)
		}
		return parts[1], convertAzureRecords(recs), nil
	}

	zones, err := scanner.ListZones(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("list Azure zones: %w", err)
	}

	var all []analyzer.Record
	for _, z := range zones {
		recs, err := scanner.ListRecords(ctx, z.ResourceGroup, z.Name)
		if err != nil {
			return "", nil, fmt.Errorf("list Azure records for zone %s: %w", z.Name, err)
		}
		all = append(all, convertAzureRecords(recs)...)
	}
	return "azure", all, nil
}

func cloudflareRecords(ctx context.Context, opts *GlobalOptions, cfg *config.Config) (string, []analyzer.Record, error) {
	token := cfg.CloudflareToken()
	if token == "" {
		return "", nil, fmt.Errorf("cloudflare API token required: set DNSSPECTRE_CLOUDFLARE_API_TOKEN or cloudflare.api_token in config")
	}

	scanner, err := cloudflare.NewScannerFromConfig(token)
	if err != nil {
		return "", nil, fmt.Errorf("create Cloudflare scanner: %w", err)
	}

	if opts.Zone != "" {
		recs, err := scanner.ListRecords(ctx, opts.Zone)
		if err != nil {
			return "", nil, fmt.Errorf("list Cloudflare records: %w", err)
		}
		return opts.Zone, convertCloudflareRecords(recs), nil
	}

	zones, err := scanner.ListZones(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("list Cloudflare zones: %w", err)
	}

	var all []analyzer.Record
	for _, z := range zones {
		recs, err := scanner.ListRecords(ctx, z.ID)
		if err != nil {
			return "", nil, fmt.Errorf("list Cloudflare records for zone %s: %w", z.Name, err)
		}
		all = append(all, convertCloudflareRecords(recs)...)
	}
	return "cloudflare", all, nil
}

func convertAWSRecords(records []aws.Record) []analyzer.Record {
	out := make([]analyzer.Record, len(records))
	for i, r := range records {
		out[i] = analyzer.Record{Name: r.Name, Type: r.Type, Values: r.Values, TTL: r.TTL}
	}
	return out
}

func convertGCPRecords(records []gcp.Record) []analyzer.Record {
	out := make([]analyzer.Record, len(records))
	for i, r := range records {
		out[i] = analyzer.Record{Name: r.Name, Type: r.Type, Values: r.Values, TTL: r.TTL}
	}
	return out
}

func convertAzureRecords(records []azure.Record) []analyzer.Record {
	out := make([]analyzer.Record, len(records))
	for i, r := range records {
		out[i] = analyzer.Record{Name: r.Name, Type: r.Type, Values: r.Values, TTL: r.TTL}
	}
	return out
}

func convertCloudflareRecords(records []cloudflare.Record) []analyzer.Record {
	out := make([]analyzer.Record, len(records))
	for i, r := range records {
		out[i] = analyzer.Record{Name: r.Name, Type: r.Type, Values: r.Values, TTL: r.TTL}
	}
	return out
}
