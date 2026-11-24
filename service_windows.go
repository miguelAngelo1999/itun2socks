//go:build windows

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows/svc"

	"github.com/igoogolx/itun2socks/internal/constants"
)

const (
	luxWindowsServiceName = "LuxCoreService"
	luxServiceMetaDir     = `C:\ProgramData\LuxService`
)

type luxWindowsService struct {
	cancel context.CancelFunc
	sup    *coreServiceSupervisor
}

func (s *luxWindowsService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	exePath, err := os.Executable()
	if err != nil {
		return false, 1
	}
	exeDir := filepath.Dir(exePath)
	// Prefer sibling lux_core.exe in the same admin-protected directory so
	// taskkill /IM lux_core.exe never terminates lux_service.exe. Fall back to
	// exePath itself if only a single binary exists.
	workerBin := filepath.Join(exeDir, "lux_core.exe")
	if _, statErr := os.Stat(workerBin); statErr != nil {
		workerBin = exePath
	}

	token, err := generateRandomTokenHex(32)
	if err != nil {
		return false, 2
	}

	ln, port, err := bindServiceListener(defaultServiceControlPort)
	if err != nil {
		return false, 3
	}

	sup, err := newCoreServiceSupervisor(workerBin, token, port, func(cmd *exec.Cmd) {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: 0x08000000, // CREATE_NO_WINDOW
		}
	})
	if err != nil {
		_ = ln.Close()
		return false, 4
	}
	s.sup = sup

	metaPath := filepath.Join(luxServiceMetaDir, serviceMetadataFileName)
	_ = writeServiceMetadataAtomic(metaPath, serviceMetadata{
		Port:       port,
		Token:      token,
		CoreSHA256: sup.workerSHA256,
		Version:    constants.Version,
		PID:        os.Getpid(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	go runServiceHTTPServer(ctx, sup, ln)

	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			cancel()
			sup.stopWorker()
			_ = os.Remove(metaPath)
			return false, 0
		}
	}
	return false, 0
}

func runWindowsService() error {
	return svc.Run(luxWindowsServiceName, &luxWindowsService{})
}
