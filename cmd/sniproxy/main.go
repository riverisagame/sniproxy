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
	"time"

	"sniproxy/internal/config"
	"sniproxy/internal/proxy"
)

// toggleSignal returns the OS signal used for toggling debug log level.
// On Linux this is SIGUSR1; on Windows it is nil (no toggle signal).
var toggleSignal os.Signal

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
		if *logFormat == "json" {
			handler = slog.NewJSONHandler(f, handlerOpts)
		} else {
			handler = slog.NewTextHandler(f, handlerOpts)
		}
	}
	logger := slog.New(handler)

	// Daemonize
	if *daemonize {
		if err := daemon(); err != nil {
			logger.Error("daemonize failed", "error", err)
			os.Exit(1)
		}
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

	sigs := []os.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM}
	if ts := toggleSignal; ts != nil {
		sigs = append(sigs, ts)
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, sigs...)

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
			case syscall.SIGINT, syscall.SIGTERM:
				logger.Info("shutting down...")
				cancel()
				return
			default:
				if sig == toggleSignal {
					newLevel := slog.LevelDebug
					if handlerOpts.Level == slog.LevelDebug {
						newLevel = level
					}
					handlerOpts.Level = newLevel
					logger.Info("log level toggled", "level", newLevel)
				}
			}
		}
	}()

	logger.Info("proxy started", "listen", cfg.Listen)

	if err := proxy.AcceptLoop(ctx, ln, cfg.Router(), logger); err != nil {
		logger.Error("accept loop error", "error", err)
	}

	logger.Info("proxy stopped")
}
