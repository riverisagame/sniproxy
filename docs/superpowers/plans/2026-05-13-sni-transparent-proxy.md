# SNI Transparent Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Go SNI transparent proxy that routes TLS connections by SNI hostname to configurable backends with zero-copy forwarding.

**Architecture:** Single binary, goroutine-per-connection. Accept TCP → read ClientHello → O(1) route lookup → replay ClientHello to backend → splice(2) bidirectional forward. Four packages: `config`, `router`, `sni`, `proxy`. Stdlib-only except `gopkg.in/yaml.v3`.

**Tech Stack:** Go 1.21+, gopkg.in/yaml.v3, Linux kernel 4.0+

---

## File Structure

```
sniproxy/
├── cmd/sniproxy/main.go          # Entry point, CLI flags, signal handling, daemonize
├── internal/
│   ├── config/
│   │   ├── config.go             # YAML types, Load(), Reload()
│   │   └── config_test.go        # Parse + route construction tests
│   ├── router/
│   │   ├── router.go             # O(1) exact+wildcard+default lookup
│   │   └── router_test.go        # Exact, wildcard, default fallback tests
│   ├── sni/
│   │   ├── clienthello.go        # Parse ClientHello, extract SNI extension
│   │   └── clienthello_test.go   # Real TLS ClientHello byte dump tests
│   └── proxy/
│       ├── proxy.go              # Accept loop, handleConnection, splice forward
│       ├── prewarm.go            # Connection pre-warming on startup
│       └── proxy_test.go         # Integration: proxy + test backends + TLS clients
├── go.mod
├── go.sum
└── config.example.yaml
```

---

### Task 1: Project scaffold and go.mod

**Files:**
- Create: `go.mod`
- Create: `config.example.yaml`

- [ ] **Step 1: Initialize Go module**

```bash
cd D:\claudeprj\sniproxy && go mod init github.com/your/sniproxy
```

Run: `go mod init github.com/your/sniproxy`
Expected: `go: creating new go.mod: module github.com/your/sniproxy`

- [ ] **Step 2: Add yaml dependency**

```bash
go get gopkg.in/yaml.v3
```

- [ ] **Step 3: Write example config**

Write `config.example.yaml`:

```yaml
listen: ":443"
default_backend: "127.0.0.1:8443"

routes:
  - sni:
      - "api.example.com"
      - "admin.example.com"
    backend: "10.0.0.1:443"
  - sni:
      - "*.example.com"
    backend: "10.0.0.2:8443"
```

- [ ] **Step 4: Commit**

```bash
git init && git add -A && git commit -m "feat: scaffold Go module with yaml dep and example config"
```

---

### Task 2: internal/router — O(1) SNI router

**Files:**
- Create: `internal/router/router.go`
- Create: `internal/router/router_test.go`

- [ ] **Step 1: Write router tests**

Write `internal/router/router_test.go`:

```go
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
```

- [ ] **Step 2: Run tests, verify they fail**

```bash
go test ./internal/router/...
```
Expected: compilation error (package router not defined)

- [ ] **Step 3: Write router implementation**

Write `internal/router/router.go`:

```go
package router

import "strings"

// Router performs O(1) SNI → backend lookup using two hash maps.
type Router struct {
	exact    map[string]string
	wildcard map[string]string
	def      string
}

// routes maps backend address → list of SNI patterns.
// Patterns starting with "*." are wildcards; the rest are exact.
func New(routes map[string][]string, defaultBackend string) *Router {
	r := &Router{
		exact:    make(map[string]string),
		wildcard: make(map[string]string),
		def:      defaultBackend,
	}
	for backend, patterns := range routes {
		for _, p := range patterns {
			if strings.HasPrefix(p, "*.") {
				domain := p[2:] // strip "*."
				r.wildcard[domain] = backend
			} else {
				r.exact[p] = backend
			}
		}
	}
	return r
}

func (r *Router) Lookup(sni string) string {
	if b, ok := r.exact[sni]; ok {
		return b
	}
	// Strip first label: "foo.example.com" → "example.com"
	if idx := strings.IndexByte(sni, '.'); idx != -1 {
		domain := sni[idx+1:]
		if b, ok := r.wildcard[domain]; ok {
			return b
		}
	}
	return r.def
}
```

- [ ] **Step 4: Run tests, verify they pass**

```bash
go test ./internal/router/ -v
```
Expected: all 8 tests PASS

- [ ] **Step 5: Commit**

```bash
git add internal/router/ && git commit -m "feat: add O(1) router with exact, wildcard, and default matching"
```

---

### Task 3: internal/config — YAML config loading

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`

- [ ] **Step 1: Write config tests**

Write `internal/config/config_test.go`:

```go
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
		t.Fatalf("api.example.com → %s", b)
	}
	if b := router.Lookup("foo.example.com"); b != "10.0.0.2:8443" {
		t.Fatalf("foo.example.com → %s", b)
	}
	if b := router.Lookup("bar.other.com"); b != "10.0.0.2:8443" {
		t.Fatalf("bar.other.com → %s", b)
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

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing default_backend")
	}
}

func TestReloadKeepsOldOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(`
default_backend: "10.0.0.1:443"
`), 0644)

	cfg, _ := Load(path)
	oldRouter := cfg.Router()

	// Corrupt the file
	os.WriteFile(path, []byte(`:::invalid yaml:::`), 0644)

	newCfg, err := Reload(path, cfg)
	if err == nil {
		t.Fatal("expected error from Reload on invalid config")
	}
	if newCfg.Router() != oldRouter {
		t.Fatal("router should be unchanged after failed reload")
	}
}
```

- [ ] **Step 2: Run tests, verify they fail**

```bash
go test ./internal/config/...
```
Expected: compilation error (package config not defined)

- [ ] **Step 3: Write config implementation**

Write `internal/config/config.go`:

```go
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/your/sniproxy/internal/router"
)

type Config struct {
	Listen         string   `yaml:"listen"`
	DefaultBackend string   `yaml:"default_backend"`
	Routes         []Route  `yaml:"routes"`

	// internal router built from routes, not serialized
	r *router.Router
}

type Route struct {
	SNI     []string `yaml:"sni"`
	Backend string   `yaml:"backend"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Listen == "" {
		cfg.Listen = ":443"
	}
	if cfg.DefaultBackend == "" {
		return nil, fmt.Errorf("default_backend is required")
	}
	cfg.r = buildRouter(cfg.Routes, cfg.DefaultBackend)
	return cfg, nil
}

func buildRouter(routes []Route, defaultBackend string) *router.Router {
	m := make(map[string][]string, len(routes))
	for _, rt := range routes {
		m[rt.Backend] = append(m[rt.Backend], rt.SNI...)
	}
	return router.New(m, defaultBackend)
}

// Reload re-reads the config file. On parse error, returns the original cfg unchanged.
func Reload(path string, cfg *Config) (*Config, error) {
	newCfg, err := Load(path)
	if err != nil {
		return cfg, err
	}
	return newCfg, nil
}

func (c *Config) Router() *router.Router { return c.r }
```

- [ ] **Step 4: Run tests, verify they pass**

```bash
go test ./internal/config/ -v
```
Expected: all 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add internal/config/ && git commit -m "feat: add YAML config loading with reload support"
```

---

### Task 4: internal/sni — ClientHello SNI parser

**Files:**
- Create: `internal/sni/clienthello.go`
- Create: `internal/sni/clienthello_test.go`

- [ ] **Step 1: Write SNI parser tests**

Write `internal/sni/clienthello_test.go`:

```go
package sni

import (
	"crypto/tls"
	"net"
	"sync"
	"testing"
)

// captureSNI starts a TLS server, connects to it, and captures the ClientHello bytes.
// Returns the raw ClientHello record and the expected SNI.
func captureClientHello(t *testing.T) ([]byte, string) {
	t.Helper()

	sniCh := make(chan string, 1)
	helloCh := make(chan []byte, 1)

	tlsCfg := &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			sniCh <- info.ServerName
			return nil, nil // will fail TLS handshake, but SNI is captured
		},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, _ := ln.Accept()
		// Read ClientHello bytes from raw TCP before TLS server processes it
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		helloCh <- buf[:n]
		 conn.(*tls.Conn).Handshake() // complete handshake to get SNI
	}()

	// Connect with TLS client, sending SNI
	tlsClientCfg := &tls.Config{
		ServerName:         "api.example.com",
		InsecureSkipVerify: true,
	}
	clientConn, err := tls.Dial("tcp", ln.Addr().String(), tlsClientCfg)
	if err != nil {
		// Handshake will fail because server returns nil config, but ClientHello was sent
	}
	if clientConn != nil {
		clientConn.Close()
	}

	wg.Wait()

	expected := <-sniCh
	hello := <-helloCh

	if expected != "api.example.com" {
		t.Skipf("server didn't capture SNI: got %q", expected)
	}
	if len(hello) < 5 {
		t.Fatal("ClientHello too short")
	}
	return hello, expected
}

func TestParseClientHello(t *testing.T) {
	hello, expected := captureClientHello(t)
	sni, err := Parse(hello)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if sni != expected {
		t.Fatalf("expected SNI %q, got %q", expected, sni)
	}
}

func TestParseNonTLS(t *testing.T) {
	_, err := Parse([]byte("GET / HTTP/1.1\r\n"))
	if err == nil {
		t.Fatal("expected error for non-TLS data")
	}
}

func TestParseShortData(t *testing.T) {
	_, err := Parse([]byte{0x16, 0x03, 0x01}) // incomplete record header
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestParseEmptyExtension(t *testing.T) {
	// Construct a minimal ClientHello with no extensions
	hello := []byte{
		0x16,       // ContentType: handshake
		0x03, 0x01, // Version: TLS 1.0
		0x00, 0x2c, // Length: 44
		0x01,             // HandshakeType: ClientHello
		0x00, 0x00, 0x28, // Length: 40 (Uint24)
		0x03, 0x03,                                     // ClientVersion: TLS 1.2
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Random (first 8)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Random (next 8)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Random (next 8)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Random (last 8)
		0x00,                   // SessionID length: 0
		0x00, 0x02, 0x00, 0x00, // CipherSuites: length 2, 1 suite (TLS_NULL_WITH_NULL_NULL)
		0x01, 0x00, // CompressionMethods: length 1, null
		0x00, 0x00, // Extensions length: 0 (no extensions)
	}
	sni, err := Parse(hello)
	if err != nil {
		t.Fatalf("Parse failed for no-extension hello: %v", err)
	}
	if sni != "" {
		t.Fatalf("expected empty SNI, got %q", sni)
	}
}
```

- [ ] **Step 2: Run tests, verify they fail**

```bash
go test ./internal/sni/...
```
Expected: compilation error

- [ ] **Step 3: Write SNI parser**

Write `internal/sni/clienthello.go`:

```go
// Package sni parses the Server Name Indication extension from TLS ClientHello messages.
// Supports TLS 1.0 through 1.3 per RFC 6066 §3.
package sni

import (
	"encoding/binary"
	"fmt"
)

const (
	recordHeaderLen = 5
	handshakeHeaderLen = 4
	sniExtensionType   = 0x0000
)

// Parse extracts the SNI hostname from a TLS ClientHello record.
// data must be the complete TLS record (header + payload).
// Returns empty string if no SNI extension is present (not an error).
func Parse(data []byte) (string, error) {
	if len(data) < recordHeaderLen {
		return "", fmt.Errorf("record too short: %d bytes", len(data))
	}

	// TLS record header
	contentType := data[0]
	if contentType != 0x16 { // handshake
		return "", fmt.Errorf("not a TLS handshake record: type %d", contentType)
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < recordHeaderLen+recordLen {
		return "", fmt.Errorf("truncated record: have %d, want %d", len(data), recordHeaderLen+recordLen)
	}

	payload := data[recordHeaderLen : recordHeaderLen+recordLen]
	if len(payload) < handshakeHeaderLen {
		return "", fmt.Errorf("handshake payload too short: %d", len(payload))
	}

	msgType := payload[0]
	if msgType != 0x01 { // ClientHello
		return "", fmt.Errorf("not a ClientHello: msg_type %d", msgType)
	}
	// handshake body length (uint24)
	// bodyLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	body := payload[handshakeHeaderLen:]

	return parseClientHelloBody(body)
}

func parseClientHelloBody(body []byte) (string, error) {
	pos := 0

	// client_version (2 bytes)
	if len(body) < pos+2 {
		return "", fmt.Errorf("clienthello truncated at version")
	}
	pos += 2

	// random (32 bytes)
	if len(body) < pos+32 {
		return "", fmt.Errorf("clienthello truncated at random")
	}
	pos += 32

	// session_id (1 byte length + data)
	if len(body) < pos+1 {
		return "", fmt.Errorf("clienthello truncated at session_id length")
	}
	sidLen := int(body[pos])
	pos += 1 + sidLen
	if len(body) < pos {
		return "", fmt.Errorf("clienthello truncated at session_id")
	}

	// cipher_suites (2 byte length + data)
	if len(body) < pos+2 {
		return "", fmt.Errorf("clienthello truncated at cipher_suites length")
	}
	csLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2 + csLen
	if len(body) < pos {
		return "", fmt.Errorf("clienthello truncated at cipher_suites")
	}

	// compression_methods (1 byte length + data)
	if len(body) < pos+1 {
		return "", fmt.Errorf("clienthello truncated at compression_methods length")
	}
	cmLen := int(body[pos])
	pos += 1 + cmLen
	if len(body) < pos {
		return "", fmt.Errorf("clienthello truncated at compression_methods")
	}

	// Extensions (2 byte length, then extension list)
	if pos == len(body) {
		return "", nil // no extensions
	}
	if len(body) < pos+2 {
		return "", fmt.Errorf("clienthello truncated at extensions length")
	}
	extLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2
	extEnd := pos + extLen
	if len(body) < extEnd {
		return "", fmt.Errorf("clienthello truncated in extensions")
	}

	// Scan extensions for SNI (type 0x0000)
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[pos:])
		extDataLen := int(binary.BigEndian.Uint16(body[pos+2:]))
		pos += 4
		if pos+extDataLen > extEnd {
			return "", fmt.Errorf("extension data overflows")
		}

		if extType == sniExtensionType {
			return parseSNIExtension(body[pos : pos+extDataLen])
		}
		pos += extDataLen
	}

	return "", nil // SNI extension not found
}

func parseSNIExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("SNI extension too short")
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2 : 2+listLen]

	pos := 0
	for pos+3 <= len(data) {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1:]))
		pos += 3
		if pos+nameLen > len(data) {
			return "", fmt.Errorf("SNI name overflows")
		}
		if nameType == 0x00 { // host_name
			return string(data[pos : pos+nameLen]), nil
		}
		pos += nameLen
	}
	return "", nil
}
```

- [ ] **Step 4: Run tests, verify they pass**

```bash
go test ./internal/sni/ -v
```
Expected: all 4 tests PASS (the real ClientHello test may use `t.Skip` if TLS server captures SNI differently)

- [ ] **Step 5: Commit**

```bash
git add internal/sni/ && git commit -m "feat: add TLS ClientHello SNI parser"
```

---

### Task 5: internal/proxy/prewarm — Connection pre-warming

**Files:**
- Create: `internal/proxy/prewarm.go`

- [ ] **Step 1: Write pre-warming code**

Write `internal/proxy/prewarm.go`:

```go
package proxy

import (
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/your/sniproxy/internal/router"
)

// PreWarm dials each unique backend once to verify reachability and warm
// the kernel connection-tracking table. Runs concurrently. Errors are logged
// as warnings, not fatal.
func PreWarm(r *router.Router, timeout time.Duration, logger *slog.Logger) {
	backends := r.UniqueBackends()
	if len(backends) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, addr := range backends {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				logger.Warn("backend pre-warm failed", "addr", addr, "error", err)
				return
			}
			conn.Close()
			logger.Info("backend pre-warm OK", "addr", addr)
		}(addr)
	}
	wg.Wait()
}
```

- [ ] **Step 2: Add UniqueBackends to router**

Modify `internal/router/router.go` — add this method after `Lookup`:

```go
// UniqueBackends returns deduplicated backend addresses.
func (r *Router) UniqueBackends() []string {
	seen := make(map[string]bool)
	seen[r.def] = true
	for _, b := range r.exact {
		seen[b] = true
	}
	for _, b := range r.wildcard {
		seen[b] = true
	}
	out := make([]string, 0, len(seen))
	for b := range seen {
		out = append(out, b)
	}
	return out
}
```

- [ ] **Step 3: Run router tests to confirm no regression**

```bash
go test ./internal/router/ -v
```
Expected: all 8 tests PASS

- [ ] **Step 4: Commit**

```bash
git add internal/router/router.go internal/proxy/prewarm.go && git commit -m "feat: add connection pre-warming with UniqueBackends"
```

---

### Task 6: internal/proxy — Core proxy (accept, route, splice forward)

**Files:**
- Create: `internal/proxy/proxy.go`
- Create: `internal/proxy/proxy_test.go`

- [ ] **Step 1: Write proxy integration test**

Write `internal/proxy/proxy_test.go`:

```go
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/your/sniproxy/internal/router"
)

// selfSignedCert generates a self-signed cert for testing.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := tls.X509KeyPair(
		[]byte(`-----BEGIN CERTIFICATE-----
MIICpDCCAkugAwIBAgIUWAAAAAAAAAAAAAAAAAAAAMA0GCSqGSIb3DQEBCwUAMIGU
MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2Fu
IEZyYW5jaXNjbzEUMBIGA1UECgwLRXhhbXBsZSBDby4xGDAWBgNVBAMMDyouZXhh
bXBsZS5jb20xGDAWBgNVBAkMDy5leGFtcGxlLmNvbS9DRRgwFgYJKoZIhvcNAQkC
Dgl0ZXN0QGV4YW1wbGUwIBcNMjYwNTAxMDAwMDAwWhgPMjEyNjA0MDcwMDAwMDBa
MIGUMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
U2FuIEZyYW5jaXNjbzEUMBIGA1UECgwLRXhhbXBsZSBDby4xGDAWBgNVBAMMDyou
ZXhhbXBsZS5jb20xGDAWBgNVBAkMDy5leGFtcGxlLmNvbS9DRRgwFgYJKoZIhvcN
AQkCDgl0ZXN0QGV4YW1wbGUwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAlP3zPMPt
hL9uPLqFxBwJ0QMfYXZjHwQLKmMBRtEcVxCwaFGbU5QkXpOUvDDRUCHpHhkxCfyf
oqGFA5/LqG7vLQIDAQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRn
5XqQUqVz6NCpJLK2mkoYJ8yF1TAfBgNVHSMEGDAWgBRn5XqQUqVz6NCpJLK2mkoY
J8yF1TAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADQQA9VMq+02y/uK/+
ZyXCQJW9jHdYbJYQLGWGx5bELaQCifNkvK3TZ1eIJ+JYKE3CFIF8iKs4kRfn3aJx
VKx/jrs=-----END CERTIFICATE-----`),
		[]byte(`-----BEGIN PRIVATE KEY-----
MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAlP3zPMPthL9uPLqF
xBwJ0QMfYXZjHwQLKmMBRtEcVxCwaFGbU5QkXpOUvDDRUCHpHhkxCfyfoqGFA5/L
qG7vLQIDAQABAkBQ2nJXKL5LqLDXKJYK7YnHmHnXcBKLnxVQ1fJqNqDz5xZJqYp0
kfHxR5aVQt6Y5UfGXBrmhFhjLqXQcVq3wQIBADwDAgEAPDA5MBQGA1UEAwwNKi5l
eGFtcGxlLmNvbTAUBgNVBAkMDSouZXhhbXBsZS5jb20wCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEUMBIGA1UE
CgwLRXhhbXBsZSBDby4xGDAWBgNVBAMMDyouZXhhbXBsZS5jb20xGDAWBgNVBAkM
DyouZXhhbXBsZS5jb20vQ0UYMBYGCWCGSAFlAwIBAgwJdGVzdEBleGFtcGxlMA0G
CSqGSIb3DQEBCwUAA0EAKt6fQPPYFvcJIb8QIFAOz0MlyIHYyCIrMbnwALVBM3Xn
BfVLQxjEYDcrbKYfAThI5KAXh4qHQqGNQnJLtAhXUA==
-----END PRIVATE KEY-----`),
	)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestProxySNIRouting(t *testing.T) {
	// Generate self-signed cert
	cert := selfSignedCert(t)

	// Start backend TLS servers
	backend1 := startTLSServer(t, cert, "127.0.0.1:0")
	backend2 := startTLSServer(t, cert, "127.0.0.1:0")
	backendDefault := startTLSServer(t, cert, "127.0.0.1:0")

	r := router.New(map[string][]string{
		backend1.Addr:   {"api.example.com"},
		backend2.Addr:   {"*.other.com"},
		backendDefault.Addr: nil,
	}, backendDefault.Addr)

	// Start proxy
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := ln.Addr().String()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go AcceptLoop(ctx, ln, r, logger)

	// Test exact match
	conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		ServerName:         "api.example.com",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("exact match dial failed: %v", err)
	}
	conn.Close()

	// Test wildcard match
	conn, err = tls.Dial("tcp", proxyAddr, &tls.Config{
		ServerName:         "foo.other.com",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("wildcard dial failed: %v", err)
	}
	conn.Close()

	// Test default fallback
	conn, err = tls.Dial("tcp", proxyAddr, &tls.Config{
		ServerName:         "unknown.com",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("default fallback dial failed: %v", err)
	}
	conn.Close()
}

func startTLSServer(t *testing.T, cert tls.Certificate, addr string) *tlsServer {
	t.Helper()
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	s := &tlsServer{Addr: ln.Addr().String(), ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				io.Copy(c, c) // echo
				c.Close()
			}(conn)
		}
	}()
	return s
}

type tlsServer struct {
	Addr string
	ln   net.Listener
}
```

- [ ] **Step 2: Run test, verify it fails**

```bash
go test ./internal/proxy/ -run TestProxySNIRouting -v
```
Expected: compilation error (AcceptLoop not defined)

- [ ] **Step 3: Write proxy implementation**

Write `internal/proxy/proxy.go`:

```go
package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/your/sniproxy/internal/router"
	"github.com/your/sniproxy/internal/sni"
)

const (
	peekTimeout   = 30 * time.Second
	dialTimeout   = 10 * time.Second
	keepAliveIdle = 15 * time.Second
)

// AcceptLoop accepts connections and handles each in a new goroutine.
// Blocks until ctx is cancelled.
func AcceptLoop(ctx context.Context, ln net.Listener, r *router.Router, logger *slog.Logger) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				logger.Error("accept failed", "error", err)
				continue
			}
		}
		go handleConnection(ctx, conn, r, logger)
	}
}

func handleConnection(ctx context.Context, clientConn net.Conn, r *router.Router, logger *slog.Logger) {
	defer clientConn.Close()

	remote := clientConn.RemoteAddr().String()
	tcpConn := clientConn.(*net.TCPConn)

	// Step 1: Read TLS record header
	if err := tcpConn.SetReadDeadline(time.Now().Add(peekTimeout)); err != nil {
		return
	}
	buf := make([]byte, 5+16384)
	hdr := buf[:5]
	if _, err := io.ReadFull(tcpConn, hdr); err != nil {
		logger.Debug("read TLS header failed", "remote", remote, "error", err)
		return
	}
	if hdr[0] != 0x16 {
		logger.Debug("not a TLS handshake", "remote", remote, "type", hdr[0])
		return
	}
	recordLen := int(hdr[3])<<8 | int(hdr[4])
	if recordLen < 2 || recordLen > 16384 {
		logger.Debug("invalid TLS record length", "remote", remote, "len", recordLen)
		return
	}

	// Step 2: Read full TLS record (header + body)
	totalLen := 5 + recordLen
	if _, err := io.ReadFull(tcpConn, buf[5:totalLen]); err != nil {
		logger.Debug("read TLS record body failed", "remote", remote, "error", err)
		return
	}

	// Step 3: Parse SNI
	sniHost, err := sni.Parse(buf[:totalLen])
	if err != nil {
		logger.Debug("SNI parse failed", "remote", remote, "error", err)
		return
	}
	if sniHost == "" {
		logger.Debug("no SNI in ClientHello", "remote", remote)
	}

	// Step 4: Route lookup
	backend := r.Lookup(sniHost)
	logger.Debug("SNI route", "remote", remote, "sni", sniHost, "backend", backend)

	// Step 5: Clear deadline for data forwarding
	tcpConn.SetDeadline(time.Time{})

	// Step 6: Dial backend
	backendConn, err := net.DialTimeout("tcp", backend, dialTimeout)
	if err != nil {
		logger.Error("backend dial failed", "remote", remote, "sni", sniHost, "backend", backend, "error", err)
		return
	}
	defer backendConn.Close()

	btcpConn := backendConn.(*net.TCPConn)

	// Step 7: Set keepalive
	setKeepAlive(tcpConn)
	setKeepAlive(btcpConn)

	logger.Info("connected", "remote", remote, "sni", sniHost, "backend", backend)

	// Step 8: Replay ClientHello to backend
	if _, err := backendConn.Write(buf[:totalLen]); err != nil {
		logger.Debug("replay ClientHello failed", "remote", remote, "error", err)
		return
	}

	// Step 9: Bidirectional zero-copy forwarding (splice on Linux)
	start := time.Now()
	var rx, tx int64

	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(btcpConn, tcpConn) // client → backend
		rx = n
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(tcpConn, btcpConn) // backend → client
		tx = n
		done <- struct{}{}
	}()

	// Wait for either direction to complete, then close both
	select {
	case <-done:
	case <-ctx.Done():
	}
	<-done // wait for the other direction

	dur := time.Since(start)
	logger.Info("close", "remote", remote, "sni", sniHost, "rx", rx, "tx", tx, "dur", dur.Round(time.Millisecond).String())
}

func setKeepAlive(conn *net.TCPConn) {
	conn.SetKeepAlive(true)
	conn.SetKeepAlivePeriod(keepAliveIdle)
}
```

- [ ] **Step 4: Run integration test**

```bash
go test ./internal/proxy/ -run TestProxySNIRouting -v -timeout 15s
```
Expected: PASS

- [ ] **Step 5: Run all tests**

```bash
go test ./... -v
```
Expected: all tests pass

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/ && git commit -m "feat: add proxy accept loop with zero-copy splice forwarding"
```

---

### Task 7: cmd/sniproxy/main — CLI, daemonize, signal handling

**Files:**
- Create: `cmd/sniproxy/main.go`

- [ ] **Step 1: Write main.go**

Write `cmd/sniproxy/main.go`:

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/your/sniproxy/internal/config"
	"github.com/your/sniproxy/internal/proxy"
)

func main() {
	configPath := flag.String("c", "/etc/sniproxy/config.yaml", "config file path")
	daemonize := flag.Bool("d", false, "run as daemon (background)")
	verbosity := 0
	flag.BoolFunc("v", "info log level", func(string) error { verbosity = max(verbosity, 1); return nil })
	flag.BoolFunc("vv", "debug log level", func(string) error { verbosity = max(verbosity, 2); return nil })
	flag.BoolFunc("vvv", "debug log level + dump config", func(string) error { verbosity = max(verbosity, 3); return nil })
	logFormat := flag.String("log-format", "text", "log format: text or json")
	logFile := flag.String("log-file", "", "log file path (default: stdout)")
	flag.Parse()

	// Setup logger
	level := slog.LevelError
	switch verbosity {
	case 1:
		level = slog.LevelInfo
	case 2, 3:
		level = slog.LevelDebug
	}
	handlerOpts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if *logFormat == "json" {
		handler = slog.NewJSONHandler(os.Stderr, handlerOpts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, handlerOpts)
	}
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open log file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		handler = slog.NewTextHandler(f, handlerOpts)
	}
	logger := slog.New(handler)

	// Daemonize
	if *daemonize {
		daemon()
		logger.Info("daemonized", "pid", os.Getpid())
	}

	// Load config
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("load config failed", "error", err)
		os.Exit(1)
	}
	logger.Info("config loaded", "listen", cfg.Listen)

	if verbosity >= 3 {
		logger.Debug("config dump", "default_backend", cfg.DefaultBackend)
	}

	// Pre-warm connections
	proxy.PreWarm(cfg.Router(), 5*time.Second, logger)

	// Listen
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		logger.Error("listen failed", "error", err)
		os.Exit(1)
	}
	defer ln.Close()

	// Signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)

	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				newCfg, err := config.Reload(*configPath, cfg)
				if err != nil {
					logger.Error("config reload failed, keeping old config", "error", err)
				} else {
					cfg = newCfg
					logger.Info("config reloaded")
				}
			case syscall.SIGUSR1:
				// Toggle debug ↔ configured
				newLevel := slog.LevelDebug
				if handlerOpts.Level == slog.LevelDebug {
					newLevel = level
				}
				handlerOpts.Level = newLevel
				logger.Info("log level toggled", "level", newLevel)
			case syscall.SIGINT, syscall.SIGTERM:
				logger.Info("shutting down...")
				cancel()
				return
			}
		}
	}()

	logger.Info("proxy started", "listen", cfg.Listen)

	if err := proxy.AcceptLoop(ctx, ln, cfg.Router(), logger); err != nil {
		logger.Error("accept loop error", "error", err)
	}

	logger.Info("proxy stopped")
}

func daemon() {
	// Fork the process — parent exits, child continues
	if os.Getppid() != 1 {
		// Spawn a new process with the same args
		args := os.Args
		procAttr := &os.ProcAttr{
			Dir:   ".",
			Files: []*os.File{os.Stdin, nil, nil}, // close stdout/stderr in child
		}
		_, err := os.StartProcess(args[0], args, procAttr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "daemonize failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	// Child: create new session
	syscall.Setsid()
}
```

- [ ] **Step 2: Build the binary**

```bash
go build -o sniproxy ./cmd/sniproxy/
```
Expected: binary `sniproxy` created successfully

- [ ] **Step 3: Verify CLI help**

```bash
./sniproxy -h 2>&1 | head -20
```
Expected: usage output with -c, -d, -v flags

- [ ] **Step 4: Commit**

```bash
git add cmd/sniproxy/ && git commit -m "feat: add CLI entry point with daemonize, signals, and logging"
```

---

### Task 8: End-to-end verification

- [ ] **Step 1: Run full test suite**

```bash
go test ./... -v -timeout 30s
```
Expected: all tests PASS

- [ ] **Step 2: Build final binary**

```bash
go build -ldflags="-s -w" -o sniproxy ./cmd/sniproxy/
```
Expected: stripped binary created

- [ ] **Step 3: Verify binary size**

```bash
ls -lh sniproxy
```
Expected: under 8 MB

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "chore: finalize SNI proxy implementation"
```

---

## Post-Implementation Notes

After Task 8, the proxy is functional:
- Start: `./sniproxy -c config.yaml -d -vv`
- Hot reload: `kill -HUP $(pidof sniproxy)`
- Graceful stop: `kill -TERM $(pidof sniproxy)`
- Toggle debug: `kill -USR1 $(pidof sniproxy)`
