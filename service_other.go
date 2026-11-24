//go:build !windows

package main

import "errors"

func runWindowsService() error {
	return errors.New("windows service mode is only supported on Windows")
}
