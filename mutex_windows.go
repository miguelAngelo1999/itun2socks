//go:build windows

package main

import (
	"errors"
	"os"
	"syscall"

	"github.com/igoogolx/itun2socks/pkg/log"
	"golang.org/x/sys/windows"
)

var singleInstanceMutex windows.Handle

func ensureSingleInstance() {
	name, err := windows.UTF16PtrFromString(`Global\LuxCoreSingleInstanceMutex`)
	if err != nil {
		return
	}
	handle, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) ||
		errors.Is(err, syscall.ERROR_ALREADY_EXISTS) ||
		errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
		log.Warnln(log.FormatLog(log.InitPrefix, "another lux_core instance is already running (Global\\LuxCoreSingleInstanceMutex), exiting cleanly"))
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
		os.Exit(0)
	}
	if err != nil {
		log.Warnln(log.FormatLog(log.InitPrefix, "warning creating single instance mutex: %v"), err)
	}
	singleInstanceMutex = handle
}
