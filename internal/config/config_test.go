package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(`
listen: ":1443"
default_backend: "10.0.0.99:8443"
routes:
  - sni:
      - "api.example.com"
    backend: "10.0.0.1:443"
  - sni:
      - "*.example.com"
      - "*.other.com"
    backend: "10.0.0.2:8443"
`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":1443" {
		t.Fatalf("listen: got %s", cfg.Listen)
	}
	if cfg.DefaultBackend != "10.0.0.99:8443" {
		t.Fatalf("default_backend: got %s", cfg.DefaultBackend)
	}
	router := cfg.Router()
	if b := router.Lookup("api.example.com"); b != "10.0.0.1:443" {
		t.Fatalf("api.example.com -> %s", b)
	}
	if b := router.Lookup("foo.example.com"); b != "10.0.0.2:8443" {
		t.Fatalf("foo.example.com -> %s", b)
	}
	if b := router.Lookup("bar.other.com"); b != "10.0.0.2:8443" {
		t.Fatalf("bar.other.com -> %s", b)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDefaultListen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(`
default_backend: "10.0.0.1:443"
`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":443" {
		t.Fatalf("expected default listen :443, got %s", cfg.Listen)
	}
}

func TestNoDefaultBackend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(`listen: ":443"`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal("expected success for config without default_backend, got:", err)
	}
	if cfg.DefaultBackend != "" {
		t.Fatal("DefaultBackend should be empty string")
	}
	if b := cfg.Router().Lookup("unknown.com"); b != "" {
		t.Fatal("expected empty backend for unknown SNI, got:", b)
	}
}

func TestReloadKeepsOldOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(`
default_backend: "10.0.0.1:443"
`), 0644)

	cfg, _ := Load(path)
	oldRouter := cfg.Router()

	// Corrupt the file (delete to simulate unrecoverable config error)
	os.Remove(path)

	newCfg, err := Reload(path, cfg)
	if err == nil {
		t.Fatal("expected error from Reload on invalid config")
	}
	if newCfg.Router() != oldRouter {
		t.Fatal("router should be unchanged after failed reload")
	}
}
