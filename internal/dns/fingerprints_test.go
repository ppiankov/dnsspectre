package dns

import "testing"

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
