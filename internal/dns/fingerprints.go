package dns

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// WO-19: yaml tags define the on-disk schema for custom fingerprint files.
// Fingerprint describes a service susceptible to subdomain takeover.
// The yaml tags also define the on-disk schema for custom fingerprint files
// loaded by LoadFingerprints.
type Fingerprint struct {
	Service      string   `yaml:"service"`       // human-readable service name
	CNAMEs       []string `yaml:"cnames"`        // CNAME substrings that identify this service
	StatusCodes  []int    `yaml:"status_codes"`  // HTTP status codes indicating unclaimed resource
	BodyPatterns []string `yaml:"body_patterns"` // substrings in HTTP response body
	NXDomain     bool     `yaml:"nxdomain"`      // NXDOMAIN on CNAME target also indicates vulnerability
}

// BuiltinFingerprints returns the default fingerprint database.
// Returns a fresh copy each time to prevent mutation.
func BuiltinFingerprints() []Fingerprint {
	return []Fingerprint{
		{
			Service:      "AWS S3",
			CNAMEs:       []string{".s3.amazonaws.com", ".s3-website"},
			StatusCodes:  []int{404},
			BodyPatterns: []string{"NoSuchBucket"},
			NXDomain:     true,
		},
		{
			Service:      "GitHub Pages",
			CNAMEs:       []string{".github.io"},
			StatusCodes:  []int{404},
			BodyPatterns: []string{"There isn't a GitHub Pages site here"},
			NXDomain:     true,
		},
		{
			Service:      "Heroku",
			CNAMEs:       []string{".herokuapp.com", ".herokudns.com"},
			StatusCodes:  []int{404},
			BodyPatterns: []string{"No such app"},
			NXDomain:     true,
		},
		{
			Service:      "Azure Blob Storage",
			CNAMEs:       []string{".blob.core.windows.net"},
			StatusCodes:  []int{404},
			BodyPatterns: []string{"BlobNotFound"},
			NXDomain:     true,
		},
		{
			Service:      "Azure Websites",
			CNAMEs:       []string{".azurewebsites.net"},
			StatusCodes:  []int{404},
			BodyPatterns: []string{"404 Web Site not found"},
			NXDomain:     true,
		},
		{
			Service:      "Azure CDN",
			CNAMEs:       []string{".azureedge.net"},
			StatusCodes:  []int{404},
			BodyPatterns: nil,
			NXDomain:     true,
		},
		{
			Service:      "Azure Traffic Manager",
			CNAMEs:       []string{".trafficmanager.net"},
			StatusCodes:  []int{404},
			BodyPatterns: nil,
			NXDomain:     true,
		},
		{
			Service:      "Shopify",
			CNAMEs:       []string{".myshopify.com"},
			StatusCodes:  []int{404},
			BodyPatterns: []string{"Sorry, this shop is currently unavailable"},
		},
		{
			Service:      "Fastly",
			CNAMEs:       []string{".fastly.net"},
			StatusCodes:  []int{500},
			BodyPatterns: []string{"Fastly error: unknown domain"},
		},
		{
			Service:      "Pantheon",
			CNAMEs:       []string{".pantheonsite.io"},
			StatusCodes:  []int{404},
			BodyPatterns: []string{"404 error unknown site"},
			NXDomain:     true,
		},
		{
			Service:      "Surge.sh",
			CNAMEs:       []string{".surge.sh"},
			StatusCodes:  []int{404},
			BodyPatterns: []string{"project not found"},
			NXDomain:     true,
		},
		{
			Service:      "Unbounce",
			CNAMEs:       []string{".unbouncepages.com"},
			StatusCodes:  []int{404},
			BodyPatterns: []string{"The requested URL was not found"},
		},
		{
			Service:      "WordPress.com",
			CNAMEs:       []string{".wordpress.com"},
			StatusCodes:  []int{404},
			BodyPatterns: []string{"Do you want to register"},
		},
		{
			Service:      "Tumblr",
			CNAMEs:       []string{".tumblr.com"},
			StatusCodes:  []int{404},
			BodyPatterns: []string{"There's nothing here"},
		},
		{
			Service:      "Ghost",
			CNAMEs:       []string{".ghost.io"},
			StatusCodes:  []int{404},
			BodyPatterns: []string{"The thing you were looking for is no longer here"},
			NXDomain:     true,
		},
		{
			Service:      "Fly.io",
			CNAMEs:       []string{".fly.dev"},
			StatusCodes:  []int{404},
			BodyPatterns: []string{"404 Not Found"},
			NXDomain:     true,
		},
		{
			Service:      "Netlify",
			CNAMEs:       []string{".netlify.app", ".netlify.com"},
			StatusCodes:  []int{404},
			BodyPatterns: []string{"Not Found - Request ID"},
			NXDomain:     true,
		},
	}
}

// MatchCNAME returns fingerprints whose CNAME patterns match the given target.
func MatchCNAME(cname string, fingerprints []Fingerprint) []Fingerprint {
	lower := strings.ToLower(cname)
	var matches []Fingerprint
	for _, fp := range fingerprints {
		for _, pattern := range fp.CNAMEs {
			if strings.Contains(lower, strings.ToLower(pattern)) {
				matches = append(matches, fp)
				break
			}
		}
	}
	return matches
}

// WO-19: LoadFingerprints reads custom fingerprints from a YAML file by path.
// LoadFingerprints reads custom fingerprints from a YAML file. The file is a
// YAML list of entries with keys: service, cnames, status_codes, body_patterns,
// nxdomain (see Fingerprint). A missing/unreadable file returns an error so a
// typo'd --fingerprints path is not silently ignored.
func LoadFingerprints(path string) ([]Fingerprint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fps []Fingerprint
	if err := yaml.Unmarshal(data, &fps); err != nil {
		return nil, fmt.Errorf("parse fingerprints %s: %w", path, err)
	}
	for i, fp := range fps {
		for _, c := range fp.CNAMEs {
			if strings.TrimSpace(c) == "" {
				return nil, fmt.Errorf("fingerprint %q (entry %d) has an empty cname pattern, which would match every target", fp.Service, i)
			}
		}
	}
	return fps, nil
}
