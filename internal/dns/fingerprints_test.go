package dns

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltinFingerprints_Count(t *testing.T) {
	fps := BuiltinFingerprints()
	if len(fps) < 17 {
		t.Errorf("expected at least 17 fingerprints, got %d", len(fps))
	}
}

func TestBuiltinFingerprints_NoDuplicateServices(t *testing.T) {
	fps := BuiltinFingerprints()
	seen := make(map[string]bool)
	for _, fp := range fps {
		if seen[fp.Service] {
			t.Errorf("duplicate service: %s", fp.Service)
		}
		seen[fp.Service] = true
	}
}

func TestBuiltinFingerprints_RequiredFields(t *testing.T) {
	fps := BuiltinFingerprints()
	for _, fp := range fps {
		if fp.Service == "" {
			t.Error("fingerprint has empty Service")
		}
		if len(fp.CNAMEs) == 0 {
			t.Errorf("fingerprint %q has no CNAMEs", fp.Service)
		}
		if len(fp.StatusCodes) == 0 {
			t.Errorf("fingerprint %q has no StatusCodes", fp.Service)
		}
	}
}

func TestMatchCNAME_Match(t *testing.T) {
	fps := BuiltinFingerprints()
	matches := MatchCNAME("mybucket.s3.amazonaws.com", fps)
	if len(matches) == 0 {
		t.Fatal("expected match for S3 CNAME")
	}
	if matches[0].Service != "AWS S3" {
		t.Errorf("expected AWS S3, got %s", matches[0].Service)
	}
}

func TestMatchCNAME_CaseInsensitive(t *testing.T) {
	fps := BuiltinFingerprints()
	matches := MatchCNAME("MYBUCKET.S3.AMAZONAWS.COM", fps)
	if len(matches) == 0 {
		t.Fatal("expected case-insensitive match for S3 CNAME")
	}
	if matches[0].Service != "AWS S3" {
		t.Errorf("expected AWS S3, got %s", matches[0].Service)
	}
}

func TestMatchCNAME_NoMatch(t *testing.T) {
	fps := BuiltinFingerprints()
	matches := MatchCNAME("foo.example.com", fps)
	if len(matches) != 0 {
		t.Errorf("expected no matches, got %d", len(matches))
	}
}

func TestBuiltinFingerprints_IsCopy(t *testing.T) {
	fps1 := BuiltinFingerprints()
	fps2 := BuiltinFingerprints()
	fps1[0].Service = "mutated"
	if fps2[0].Service == "mutated" {
		t.Error("BuiltinFingerprints returned shared slice, not a copy")
	}
}

func TestMatchCNAME_GitHubPages(t *testing.T) {
	fps := BuiltinFingerprints()
	matches := MatchCNAME("myuser.github.io", fps)
	if len(matches) == 0 {
		t.Fatal("expected match for GitHub Pages CNAME")
	}
	if matches[0].Service != "GitHub Pages" {
		t.Errorf("expected GitHub Pages, got %s", matches[0].Service)
	}
}

func TestMatchCNAME_Heroku(t *testing.T) {
	fps := BuiltinFingerprints()
	matches := MatchCNAME("myapp.herokuapp.com", fps)
	if len(matches) == 0 {
		t.Fatal("expected match for Heroku CNAME")
	}
	if matches[0].Service != "Heroku" {
		t.Errorf("expected Heroku, got %s", matches[0].Service)
	}
}

func TestLoadFingerprints(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")
	content := `- service: Custom CDN
  cnames: [".customcdn.example"]
  status_codes: [404]
  body_patterns: ["no such site"]
  nxdomain: true
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	fps, err := LoadFingerprints(path)
	if err != nil {
		t.Fatalf("LoadFingerprints: %v", err)
	}
	if len(fps) != 1 {
		t.Fatalf("want 1 fingerprint, got %d", len(fps))
	}
	if fps[0].Service != "Custom CDN" {
		t.Errorf("service: want Custom CDN, got %q", fps[0].Service)
	}
	if len(fps[0].CNAMEs) != 1 || fps[0].CNAMEs[0] != ".customcdn.example" {
		t.Errorf("cnames: want [.customcdn.example], got %v", fps[0].CNAMEs)
	}
	if !fps[0].NXDomain {
		t.Error("nxdomain: want true")
	}
}

func TestLoadFingerprints_MissingFile(t *testing.T) {
	if _, err := LoadFingerprints(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadFingerprints_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte(":\n  - [unclosed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFingerprints(path); err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadFingerprints_RejectsEmptyPattern(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	content := "- service: Broken\n  cnames: [\"\"]\n  status_codes: [404]\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFingerprints(path); err == nil {
		t.Fatal("expected error for empty cname pattern, got nil")
	}
}
