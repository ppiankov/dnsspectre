package dns

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const maxBodySize = 1 << 20 // 1 MB

// CheckResult holds the outcome of an HTTP-based fingerprint check.
type CheckResult struct {
	Matched     bool
	Service     string
	StatusCode  int
	BodySnippet string
}

// Checker performs HTTP requests to verify fingerprint matches.
type Checker struct {
	client *http.Client
}

// NewChecker creates a Checker with the given HTTP client.
// If client is nil, a default client is used.
func NewChecker(client *http.Client) *Checker {
	if client == nil {
		client = &http.Client{}
	}
	return &Checker{client: client}
}

// Check fetches the given URL and matches the response against fingerprints.
// Returns nil result (not error) if no fingerprint matches.
func (c *Checker) Check(ctx context.Context, url string, fingerprints []Fingerprint) (*CheckResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request for %s: %w", url, err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, fmt.Errorf("read body from %s: %w", url, err)
	}
	bodyStr := string(body)

	for _, fp := range fingerprints {
		if matchesFingerprint(resp.StatusCode, bodyStr, fp) {
			return &CheckResult{
				Matched:     true,
				Service:     fp.Service,
				StatusCode:  resp.StatusCode,
				BodySnippet: truncate(bodyStr, 200),
			}, nil
		}
	}

	return nil, nil
}

func matchesFingerprint(statusCode int, body string, fp Fingerprint) bool {
	statusMatch := false
	for _, code := range fp.StatusCodes {
		if statusCode == code {
			statusMatch = true
			break
		}
	}
	if !statusMatch {
		return false
	}

	if len(fp.BodyPatterns) == 0 {
		return true
	}

	bodyLower := strings.ToLower(body)
	for _, pattern := range fp.BodyPatterns {
		if strings.Contains(bodyLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
