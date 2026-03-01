package dns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChecker_MatchS3(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte("<Error><Code>NoSuchBucket</Code></Error>"))
	}))
	defer srv.Close()

	c := NewChecker(srv.Client())
	fps := []Fingerprint{{
		Service:      "AWS S3",
		CNAMEs:       []string{".s3.amazonaws.com"},
		StatusCodes:  []int{404},
		BodyPatterns: []string{"NoSuchBucket"},
	}}

	result, err := c.Check(context.Background(), srv.URL, fps)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Matched {
		t.Fatal("expected S3 match")
	}
	if result.Service != "AWS S3" {
		t.Errorf("expected AWS S3, got %s", result.Service)
	}
	if result.StatusCode != 404 {
		t.Errorf("expected 404, got %d", result.StatusCode)
	}
}

func TestChecker_MatchGitHubPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte("There isn't a GitHub Pages site here."))
	}))
	defer srv.Close()

	c := NewChecker(srv.Client())
	fps := BuiltinFingerprints()

	result, err := c.Check(context.Background(), srv.URL, fps)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Matched {
		t.Fatal("expected GitHub Pages match")
	}
	if result.Service != "GitHub Pages" {
		t.Errorf("expected GitHub Pages, got %s", result.Service)
	}
}

func TestChecker_NoMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("Welcome to my website"))
	}))
	defer srv.Close()

	c := NewChecker(srv.Client())
	fps := BuiltinFingerprints()

	result, err := c.Check(context.Background(), srv.URL, fps)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected no match, got service %s", result.Service)
	}
}

func TestChecker_StatusOnlyMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte("some generic error page"))
	}))
	defer srv.Close()

	c := NewChecker(srv.Client())
	fps := []Fingerprint{{
		Service:      "Azure CDN",
		CNAMEs:       []string{".azureedge.net"},
		StatusCodes:  []int{404},
		BodyPatterns: nil,
	}}

	result, err := c.Check(context.Background(), srv.URL, fps)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Matched {
		t.Fatal("expected status-only match")
	}
	if result.Service != "Azure CDN" {
		t.Errorf("expected Azure CDN, got %s", result.Service)
	}
}

func TestChecker_StatusMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("NoSuchBucket"))
	}))
	defer srv.Close()

	c := NewChecker(srv.Client())
	fps := []Fingerprint{{
		Service:      "AWS S3",
		CNAMEs:       []string{".s3.amazonaws.com"},
		StatusCodes:  []int{404},
		BodyPatterns: []string{"NoSuchBucket"},
	}}

	result, err := c.Check(context.Background(), srv.URL, fps)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected no match when status code doesn't match")
	}
}

func TestChecker_BodyMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte("Page not found"))
	}))
	defer srv.Close()

	c := NewChecker(srv.Client())
	fps := []Fingerprint{{
		Service:      "AWS S3",
		CNAMEs:       []string{".s3.amazonaws.com"},
		StatusCodes:  []int{404},
		BodyPatterns: []string{"NoSuchBucket"},
	}}

	result, err := c.Check(context.Background(), srv.URL, fps)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Error("expected no match when body doesn't match")
	}
}

func TestChecker_ContextTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := NewChecker(srv.Client())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.Check(ctx, srv.URL, BuiltinFingerprints())
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestChecker_LargeBody(t *testing.T) {
	large := strings.Repeat("x", 2<<20) // 2 MB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(large))
	}))
	defer srv.Close()

	c := NewChecker(srv.Client())
	fps := []Fingerprint{{
		Service:      "Test",
		CNAMEs:       []string{".test.com"},
		StatusCodes:  []int{404},
		BodyPatterns: nil,
	}}

	result, err := c.Check(context.Background(), srv.URL, fps)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Matched {
		t.Fatal("expected status-only match even with large body")
	}
}

func TestChecker_NilClient(t *testing.T) {
	c := NewChecker(nil)
	if c == nil {
		t.Fatal("NewChecker(nil) returned nil")
	}
	if c.client == nil {
		t.Fatal("NewChecker(nil) did not create default client")
	}
}

func TestMatchesFingerprint_Direct(t *testing.T) {
	fp := Fingerprint{
		Service:      "Test",
		StatusCodes:  []int{404, 500},
		BodyPatterns: []string{"error message"},
	}

	if !matchesFingerprint(404, "some error message here", fp) {
		t.Error("expected match for 404 + body pattern")
	}
	if !matchesFingerprint(500, "Error Message", fp) {
		t.Error("expected case-insensitive body match")
	}
	if matchesFingerprint(200, "error message", fp) {
		t.Error("expected no match for wrong status code")
	}
	if matchesFingerprint(404, "no match here", fp) {
		t.Error("expected no match when body doesn't contain pattern")
	}
}
