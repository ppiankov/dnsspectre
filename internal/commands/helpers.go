package commands

import (
	"fmt"
	"time"
)

// GlobalOptions holds flag values shared across all subcommands.
type GlobalOptions struct {
	Platform     string
	Domain       string
	Zone         string
	Format       string
	Timeout      time.Duration
	Fingerprints string
}

// VersionInfo holds build metadata injected via ldflags.
type VersionInfo struct {
	Version string
	Commit  string
	Date    string
}

var validPlatforms = map[string]bool{
	"aws":        true,
	"gcp":        true,
	"azure":      true,
	"cloudflare": true,
}

var validFormats = map[string]bool{
	"json":       true,
	"text":       true,
	"sarif":      true,
	"spectrehub": true,
}

// ValidatePlatform checks that the platform value is accepted.
// Empty string is valid (means DNS query mode).
func ValidatePlatform(p string) error {
	if p == "" {
		return nil
	}
	if !validPlatforms[p] {
		return fmt.Errorf("unsupported platform %q: must be one of aws, gcp, azure, cloudflare", p)
	}
	return nil
}

// ValidateFormat checks that the format value is accepted.
func ValidateFormat(f string) error {
	if !validFormats[f] {
		return fmt.Errorf("unsupported format %q: must be one of json, text, sarif, spectrehub", f)
	}
	return nil
}
