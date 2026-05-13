package router

import "testing"

func TestExactMatch(t *testing.T) {
	r := New(map[string][]string{
		"10.0.0.1:443": {"api.example.com"},
	}, "127.0.0.1:8443")
	if got := r.Lookup("api.example.com"); got != "10.0.0.1:443" {
		t.Fatalf("expected 10.0.0.1:443, got %s", got)
	}
}

func TestWildcardMatch(t *testing.T) {
	r := New(map[string][]string{
		"10.0.0.2:8443": {"*.example.com"},
	}, "127.0.0.1:8443")
	if got := r.Lookup("foo.example.com"); got != "10.0.0.2:8443" {
		t.Fatalf("expected 10.0.0.2:8443, got %s", got)
	}
}

func TestWildcardDoesNotMatchSubSubdomain(t *testing.T) {
	r := New(map[string][]string{
		"10.0.0.2:8443": {"*.example.com"},
	}, "127.0.0.1:8443")
	if got := r.Lookup("a.b.example.com"); got != "127.0.0.1:8443" {
		t.Fatalf("expected default 127.0.0.1:8443, got %s", got)
	}
}

func TestDefaultFallback(t *testing.T) {
	r := New(map[string][]string{}, "127.0.0.1:8443")
	if got := r.Lookup("unknown.com"); got != "127.0.0.1:8443" {
		t.Fatalf("expected default, got %s", got)
	}
}

func TestExactWinsOverWildcard(t *testing.T) {
	r := New(map[string][]string{
		"10.0.0.1:443":  {"api.example.com"},
		"10.0.0.2:8443": {"*.example.com"},
	}, "127.0.0.1:8443")
	if got := r.Lookup("api.example.com"); got != "10.0.0.1:443" {
		t.Fatalf("expected exact match 10.0.0.1:443, got %s", got)
	}
}

func TestEmptySNI(t *testing.T) {
	r := New(map[string][]string{
		"10.0.0.1:443": {"api.example.com"},
	}, "127.0.0.1:8443")
	if got := r.Lookup(""); got != "127.0.0.1:8443" {
		t.Fatalf("expected default for empty SNI, got %s", got)
	}
}

func TestSingleLabel(t *testing.T) {
	r := New(map[string][]string{
		"10.0.0.1:443": {"*.com"},
	}, "127.0.0.1:8443")
	if got := r.Lookup("foo.com"); got != "10.0.0.1:443" {
		t.Fatalf("expected 10.0.0.1:443, got %s", got)
	}
}

func TestNumericWildcardIsExact(t *testing.T) {
	r := New(map[string][]string{
		"10.0.0.1:443": {"*.10.0.0.1"},
	}, "127.0.0.1:8443")
	if got := r.Lookup("*.10.0.0.1"); got != "10.0.0.1:443" {
		t.Fatalf("asterisk in host treated as exact, got %s", got)
	}
}
