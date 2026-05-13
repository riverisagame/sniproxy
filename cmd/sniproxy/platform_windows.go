//go:build windows

package main

import (
	"os"
)

// extraSignals returns signals specific to Windows (none).
func extraSignals() []os.Signal {
	return nil
}

// daemon is not supported on Windows; returns nil (no-op).
func daemon() error {
	return nil
}
