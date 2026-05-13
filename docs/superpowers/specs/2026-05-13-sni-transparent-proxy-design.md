# SNI Transparent Proxy Design Spec

## Understanding Summary

- **What**: A Go-based SNI transparent proxy that routes TLS connections by SNI hostname to configurable backends.
- **Why**: Production traffic routing — different domains need to reach different backend services without TLS termination.
- **Who**: Linux server operators, deployed as a systemd service.
- **Key constraints**: Zero-copy forwarding (splice), high concurrency, high reliability, Linux only.
- **Non-goals**: TLS termination, HTTP parsing, Windows/macOS support, anycast or multi-node coordination.

## Assumptions

- Linux kernel 4.0+ (splice support between TCP sockets).
- Go 1.21+ (slog available in stdlib).
- Backend services speak TLS; proxy only reads SNI in ClientHello, does not decrypt.
- Single process, single listen port (no multi-port listener needed).
- Config file is under administrator control; no dynamic API for config changes.

## Decision Log

| # | Decision | Alternatives | Why |
|---|----------|-------------|-----|
| 1 | Stdlib + yaml.v3 only | viper+zap, framework-based | Minimal deps, best perf, no maintenance burden |
| 2 | Two-level hash router (exact + wildcard) | Linear scan, radix tree | O(1) lookup with 2 map accesses, simple |
| 3 | `io.Copy` on raw `*net.TCPConn` for splice | Custom splice syscall wrappers | Go runtime auto-uses splice between TCP conns |
| 4 | SIGHUP hot reload | HTTP config API, inotify | Standard Unix pattern, no extra listening port |
| 5 | YAML config format | JSON, TOML | Best readability in ops community |
| 6 | `slog` for logging | zap, zerolog, logrus | Stdlib as of Go 1.21, structured by default, zero deps |

## Architecture

```
Client ──▶ TCP Accept ──▶ goroutine per connection
                              │
                              ├── 1. Peek ClientHello (bufio.Peek, ~300 bytes, 30s timeout)
                              ├── 2. Parse SNI from ClientHello
                              ├── 3. Router.Lookup(SNI) → backend address
                              ├── 4. Dial backend
                              ├── 5. Replay ClientHello to backend
                              └── 6. splice(2) bidirectional forward (io.Copy × 2)
```

Four packages:

| Package | Responsibility |
|---------|---------------|
| `config` | YAML parsing, route table construction, atomic swap on SIGHUP |
| `sni`   | ClientHello SNI extraction (RFC 6066 §3, TLS 1.0–1.3) |
| `proxy` | Accept loop, connection lifecycle, Peek→Route→Dial→Splice |
| `log`   | `slog` wrapper: level mapping (-v/-vv/-vvv), format switch (text/json) |

## Configuration Format

```yaml
# /etc/sniproxy/config.yaml
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

### Routing Algorithm (O(1), zero iteration)

```go
type Router struct {
    exact    map[string]string  // "api.example.com" → backend
    wildcard map[string]string  // "example.com" → backend
    default  string
}

func (r *Router) Lookup(sni string) string {
    if b, ok := r.exact[sni]; ok {
        return b  // 1 hash lookup
    }
    _, domain := splitFirstLabel(sni)
    if b, ok := r.wildcard[domain]; ok {
        return b  // 1 more hash lookup
    }
    return r.default
}
```

## Hot Reload

- On `SIGHUP`: read config file → build new Router → atomic pointer swap (`sync/atomic` or `atomic.Pointer[Router]`).
- Existing connections continue using old router; new connections use new router.

## Forwarding Path (Zero-Copy)

```
clientConn ──[ClientHello peeked & parsed]── backendConn
    │                                              │
    └──────── io.Copy(clientConn, backendConn) ────┘
    └──────── io.Copy(backendConn, clientConn) ────┘
              │
              Go runtime detects both are *net.TCPConn
              → calls splice(2)
              → data moves kernel-space only, zero user-space copy
```

- ClientHello is read via `bufio.Reader.Peek()` — data stays in buffer, not consumed.
- On dial success, buffered bytes replayed to backend via `bufio.Reader`. The reader is then discarded; all subsequent forwarding uses raw `*net.TCPConn` to ensure splice eligibility.
- Peek phase: 30s deadline to prevent slow-loris; forwarding phase: no deadline (long-lived connection support).

### Keepalive

Both client and backend sockets set `SO_KEEPALIVE`:

```go
rawConn.SetKeepAlive(true)
rawConn.SetKeepAlivePeriod(15 * time.Second)
```

Prevents idle connections from being dropped by intermediate NAT/firewall state tracking. Keepalive probes start after 15s idle, retry at 15s intervals.

### Connection Pre-warming

On startup (before accept loop), dial each unique backend once:

1. Iterate all routes + default_backend, deduplicate by address.
2. Dial each backend with a short connect timeout (5s).
3. Log reachability status. A pre-warm failure is a warning, not fatal — the proxy starts anyway.
4. These connections are immediately closed; the purpose is to verify backend reachability and warm the kernel's connection tracking table (conntrack).

Pre-warming runs concurrently for all unique backends.

## CLI

```
sniproxy -c /etc/sniproxy/config.yaml          # foreground
sniproxy -c /etc/sniproxy/config.yaml -d       # daemonize
sniproxy -c /etc/sniproxy/config.yaml -d -vv   # daemon + debug
```

| Flag | Effect |
|------|--------|
| `-c` | Config file path (default `/etc/sniproxy/config.yaml`) |
| `-d` | Daemonize (fork, close stdio, setsid) |
| `-v` | Log level info (default: error) |
| `-vv` | Log level debug |
| `-vvv` | Log level debug + dump config on startup |
| `-log-format` | `text` (default) or `json` |
| `-log-file` | Log file path (default: stdout) |

### Signals

| Signal | Action |
|--------|--------|
| `SIGHUP` | Hot reload config |
| `SIGTERM` / `SIGINT` | Graceful shutdown (stop accept, drain connections) |
| `SIGUSR1` | Toggle log level debug ↔ configured |

## Graceful Shutdown

1. `SIGTERM` received.
2. Stop accepting new connections.
3. Signal all active goroutines via context.
4. Wait up to 30s for active connections to close.
5. Force close remaining connections, exit.

## Error Handling

- ClientHello parse failure: log at debug level, close connection (not a TLS client or malformed).
- Backend dial failure: log at error level with SNI and backend addr, close client connection.
- Config parse error on reload: log error, keep old config (no disruption).
- Idle connection: no explicit timeout (production long-lived connections).
- Connection count limit: configurable `max_connections` (default 0 = unlimited).

## Testing Strategy

- Unit tests: `sni` package (ClientHello parsing), `config` package (route matching, wildcard logic).
- Integration test: start proxy with test config, spin up test TLS backends, make TLS connections, verify routing and SNI passthrough.
- Benchmark: concurrent connections, verify splice path via `/proc/self/fdinfo` (splice count).
