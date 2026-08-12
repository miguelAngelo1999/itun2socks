package manager

import (
	"errors"
	"sync"
	"time"

	"github.com/igoogolx/itun2socks/internal/blackbox"
	"github.com/igoogolx/itun2socks/internal/executor"
	"github.com/igoogolx/itun2socks/pkg/log"
)

var (
	client executor.Client
	mux    sync.Mutex
)

func Start() error {
	mux.Lock()
	defer mux.Unlock()
	var err, startErr, closeErr error
	defer func() {
		if err != nil || startErr != nil || closeErr != nil {
			client = nil
		}
	}()
	if GetIsStarted() {
		return errors.New("the client has started")
	}
	client, err = executor.New()
	if err != nil {
		blackbox.Record("manager-start-failed", "executor.New: "+err.Error(), nil)
		return err
	}
	startErr = client.Start()
	if startErr != nil {
		log.Errorln(log.FormatLog(log.ExecutorPrefix, "fail to start the client: %v"), startErr)
		blackbox.Record("manager-start-failed", "client.Start: "+startErr.Error(), nil)
		closeErr = client.Close()
		if closeErr != nil {
			log.Errorln(log.FormatLog(log.ExecutorPrefix, "fail to close the client: %v"), closeErr)
		}
		return startErr
	}
	log.Infoln("%s", log.FormatLog(log.ExecutorPrefix, "started the client successfully"))
	blackbox.ManagerStarted()
	// Start a health check loop that probes every 30 seconds.
	blackbox.StartHealthCheck(30*time.Second, "")
	return nil
}

func Close() error {
	mux.Lock()
	defer mux.Unlock()
	blackbox.StopHealthCheck()
	if client != nil {
		err := client.Close()
		client = nil
		if err != nil {
			blackbox.ManagerStopped("error: " + err.Error())
			return err
		}
	}
	log.Infoln("%s", log.FormatLog(log.ExecutorPrefix, "stopped the client successfully"))
	blackbox.ManagerStopped("clean shutdown")
	return nil
}

func GetIsStarted() bool {
	return client != nil
}

func RuntimeDetail(hubAddress string) (any, error) {
	return client.RuntimeDetail(hubAddress)
}
