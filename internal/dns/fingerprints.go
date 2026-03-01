package dns

import "strings"

// Fingerprint describes a service susceptible to subdomain takeover.
type Fingerprint struct {
	Service      string   // human-readable service name
	CNAMEs       []string // CNAME substrings that identify this service
	StatusCodes  []int    // HTTP status codes indicating unclaimed resource
	BodyPatterns []string // substrings in HTTP response body
	NXDomain     bool     // NXDOMAIN on CNAME target also indicates vulnerability
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
