//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

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
		log.Warnln(log.FormatLog(log.InitPrefix, "another lux_core instance is detected (Global\\LuxCoreSingleInstanceMutex), terminating zombie instances..."))
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
		// Terminate any other lux_core / itun2socks process that is not our own PID
		myPid := os.Getpid()
		_ = exec.Command("taskkill", "/F", "/FI", fmt.Sprintf("PID ne %d", myPid), "/IM", "lux_core.exe").Run()
		_ = exec.Command("taskkill", "/F", "/FI", fmt.Sprintf("PID ne %d", myPid), "/IM", "itun2socks.exe").Run()
		time.Sleep(500 * time.Millisecond)

		// Try acquiring mutex again
		handle, err = windows.CreateMutex(nil, false, name)
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) ||
			errors.Is(err, syscall.ERROR_ALREADY_EXISTS) ||
			errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
			errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			log.Warnln(log.FormatLog(log.InitPrefix, "mutex still held, exiting"))
			if handle != 0 {
				_ = windows.CloseHandle(handle)
			}
			os.Exit(0)
		}
	}
	if err != nil {
		log.Warnln(log.FormatLog(log.InitPrefix, "warning creating single instance mutex: %v"), err)
	}
	singleInstanceMutex = handle
}
