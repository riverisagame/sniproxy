//go:build linux

package main

import (
	"os"
	"os/exec"
	"syscall"
)

func init() {
	toggleSignal = syscall.SIGUSR1
}

// daemon forks the current process and exits the parent.
func daemon() error {
	if os.Getppid() != 1 {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		cmd := exec.Command(exe, os.Args[1:]...)
		cmd.Stdin = nil
		cmd.Stdout = nil
		cmd.Stderr = nil
		if err := cmd.Start(); err != nil {
			return err
		}
		os.Exit(0)
	}
	return syscall.Setsid()
}
