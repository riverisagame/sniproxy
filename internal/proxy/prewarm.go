package proxy

import (
	"log/slog"
	"net"
	"sync"
	"time"

	"sniproxy/internal/router"
)

// PreWarm dials each unique backend once to verify reachability and warm
// the kernel connection-tracking table. Runs concurrently.
// Errors are logged as warnings, not fatal — the proxy starts anyway.
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
