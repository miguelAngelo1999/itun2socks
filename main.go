package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/igoogolx/itun2socks/api"
	"github.com/igoogolx/itun2socks/internal/configuration"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/internal/manager"
	"github.com/igoogolx/itun2socks/pkg/log"
	"github.com/igoogolx/itun2socks/pkg/sysproxy"
)

var (
	homeDir     string
	version     bool
	port        int
	secret      string
	serviceMode bool
	userSID     string
)

var packageName = "itun2socks"

//go:generate go run scripts/generate.go
func main() {

	userConfigDir, _ := os.UserConfigDir()
	defaultHomeDir := filepath.Join(userConfigDir, packageName)

	flag.IntVar(&port, "port", 0, "set running port")
	flag.StringVar(&homeDir, "home_dir", defaultHomeDir, "set configuration directory")
	flag.BoolVar(&version, "version", false, "print current version of itun2socks")
	flag.StringVar(&secret, "secret", "", "set secret")
	flag.BoolVar(&serviceMode, "service", false, "run as Windows service supervisor (LuxCoreService)")
	flag.StringVar(&userSID, "user_sid", "", "target Windows user SID for per-user proxy registry updates")
	flag.Parse()

	if version {
		fmt.Printf("version: %v, build on: %v", constants.Version, constants.BuildTime)
		os.Exit(0)
	}

	if serviceMode {
		if err := runWindowsService(); err != nil {
			fmt.Fprintf(os.Stderr, "service failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if userSID != "" {
		sysproxy.SetTargetUserSID(userSID)
	}

	if !filepath.IsAbs(homeDir) {
		currentDir, _ := os.Getwd()
		homeDir = filepath.Join(currentDir, homeDir)
	}
	if runtime.GOOS == "windows" {
		homeDir = reconcileWindowsHomeDir(homeDir, userConfigDir)
	}
	_ = os.MkdirAll(homeDir, os.ModePerm)
	constants.Path.SetHomeDir(homeDir)
	log.InitLog()
	ensureSingleInstance()
	log.Infoln(log.FormatLog(log.InitPrefix, "using config: %v"), constants.Path.ConfigFilePath())
	configuration.SetConfigFilePath(constants.Path.ConfigFilePath())
	configuration.Init()
	api.Start(port, secret)

	defer func() {
		if p := recover(); p != nil {
			log.Errorln(log.FormatLog(log.InitPrefix, "internal error: %v"), p)
		}
		err := manager.Close()
		if err != nil {
			log.Errorln(log.FormatLog(log.InitPrefix, "fail to close client:%v"), err)
		}
	}()
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGHUP)
	<-osSignals
}

func reconcileWindowsHomeDir(homeDir, userConfigDir string) string {
	targetDir := homeDir
	var legacyDir, canonicalDir string

	if strings.Contains(homeDir, "com.github.igoogolx.lux") {
		// homeDir is legacy, derive canonical sibling in same parent directory
		parent := filepath.Dir(filepath.Dir(homeDir)) // 1.0 -> com.github.igoogolx.lux -> Roaming
		canonicalDir = filepath.Join(parent, "com.github.igoogolx", "lux", filepath.Base(homeDir))
		legacyDir = homeDir
		targetDir = canonicalDir
	} else if strings.Contains(homeDir, filepath.Join("com.github.igoogolx", "lux")) {
		// homeDir is already canonical, derive legacy sibling in same parent directory
		parent := filepath.Dir(filepath.Dir(filepath.Dir(homeDir))) // 1.0 -> lux -> com.github.igoogolx -> Roaming
		legacyDir = filepath.Join(parent, "com.github.igoogolx.lux", filepath.Base(homeDir))
		canonicalDir = homeDir
		targetDir = canonicalDir
	} else {
		// Custom home directory, honor it directly without rewriting
		return homeDir
	}

	_ = os.MkdirAll(targetDir, os.ModePerm)

	legacyCfg := filepath.Join(legacyDir, "config.json")
	targetCfg := filepath.Join(targetDir, "config.json")

	if lfi, err := os.Stat(legacyCfg); err == nil {
		tfi, terr := os.Stat(targetCfg)
		shouldMigrate := false
		if os.IsNotExist(terr) {
			shouldMigrate = true
		} else if terr == nil && lfi.ModTime().After(tfi.ModTime()) {
			shouldMigrate = true
		}

		if shouldMigrate {
			if data, err := os.ReadFile(legacyCfg); err == nil && len(data) > 0 {
				_ = os.WriteFile(targetCfg, data, 0666)
			}
		}
	}

	return targetDir
}
