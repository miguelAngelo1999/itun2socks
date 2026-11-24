package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/igoogolx/itun2socks/internal/constants"
)

const (
	defaultServiceControlPort = 41957
	serviceMetadataFileName   = "service.json"
)

var (
	validServiceSecretRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	validServiceSIDRe    = regexp.MustCompile(`^S-1-5-[0-9-]+$`)
)

// serviceMetadata is written by LuxCoreService on startup so the non-elevated
// Lux GUI can discover the control port, control bearer token, and installed
// worker SHA-256 without prompting UAC.
type serviceMetadata struct {
	Port       int    `json:"port"`
	Token      string `json:"token"`
	CoreSHA256 string `json:"coreSha256"`
	Version    string `json:"version"`
	PID        int    `json:"pid"`
}

type startCoreRequest struct {
	HomeDir string `json:"homeDir"`
	Port    int    `json:"port"`
	Secret  string `json:"secret"`
	UserSID string `json:"userSid"`
}

type serviceHealthResponse struct {
	OK         bool   `json:"ok"`
	CoreSHA256 string `json:"coreSha256"`
	Version    string `json:"version"`
	Running    bool   `json:"running"`
	CorePort   int    `json:"corePort"`
	CorePID    int    `json:"corePid"`
}

// validateStartCoreRequest enforces strict allow-lists on every parameter that
// a non-admin desktop user may pass to LuxCoreService. Because the service
// runs as LocalSystem, it MUST NEVER launch caller-supplied binaries or pass
// arbitrary paths/flags.
func validateStartCoreRequest(req startCoreRequest, controlPort int) error {
	if req.Port < 1024 || req.Port > 65535 || req.Port == controlPort {
		return fmt.Errorf("invalid port: %d", req.Port)
	}
	if !validServiceSecretRe.MatchString(req.Secret) {
		return errors.New("invalid secret format")
	}
	if req.UserSID != "" && !validServiceSIDRe.MatchString(req.UserSID) {
		return errors.New("invalid userSid format")
	}
	if !isAllowedLuxHomeDir(req.HomeDir) {
		return errors.New("invalid homeDir path")
	}
	return nil
}

// isAllowedLuxHomeDir checks that dir is an absolute Lux user data directory
// without path traversal segments.
func isAllowedLuxHomeDir(dir string) bool {
	trimmed := strings.TrimSpace(dir)
	if trimmed == "" {
		return false
	}
	// Reject path traversal or control characters before normalization.
	if strings.Contains(trimmed, "..") || strings.ContainsAny(trimmed, "\r\n\x00\"'`|;&<>") {
		return false
	}
	norm := strings.ToLower(strings.ReplaceAll(trimmed, "/", `\`))
	norm = strings.TrimRight(norm, `\`)

	// Accept either a Windows drive-rooted path (C:\...) or a POSIX absolute
	// path (/...) for cross-platform unit tests.
	isWinAbs := len(norm) >= 3 && norm[0] >= 'a' && norm[0] <= 'z' && norm[1] == ':' && norm[2] == '\\'
	isPosixAbs := strings.HasPrefix(trimmed, "/")
	if !isWinAbs && !isPosixAbs {
		return false
	}

	allowedSuffixes := []string{
		`\com.github.igoogolx\lux\1.0`,
		`\com.github.igoogolx.lux\1.0`,
		`\com.github.igoogolx\lux`,
		`\com.github.igoogolx.lux`,
	}
	for _, s := range allowedSuffixes {
		if strings.HasSuffix(norm, s) {
			return true
		}
	}
	return false
}

func computeFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func generateRandomTokenHex(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

type managedWorker struct {
	cmd    *exec.Cmd
	port   int
	secret string
	done   chan struct{}
}

// coreServiceSupervisor supervises a single elevated lux_core worker process
// on behalf of the non-elevated Lux GUI.
type coreServiceSupervisor struct {
	workerBinaryPath string
	workerSHA256     string
	controlToken     string
	controlPort      int
	configureCmd     func(*exec.Cmd)

	mu     sync.Mutex
	worker *managedWorker
}

func newCoreServiceSupervisor(workerBinaryPath, controlToken string, controlPort int, configureCmd func(*exec.Cmd)) (*coreServiceSupervisor, error) {
	hash, err := computeFileSHA256(workerBinaryPath)
	if err != nil {
		return nil, fmt.Errorf("hash worker binary %s: %w", workerBinaryPath, err)
	}
	return &coreServiceSupervisor{
		workerBinaryPath: workerBinaryPath,
		workerSHA256:     hash,
		controlToken:     controlToken,
		controlPort:      controlPort,
		configureCmd:     configureCmd,
	}, nil
}

func (s *coreServiceSupervisor) isAuthorized(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	given := auth[len(prefix):]
	return subtle.ConstantTimeCompare([]byte(given), []byte(s.controlToken)) == 1
}

func (s *coreServiceSupervisor) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/status", s.requireAuth(s.handleHealth))
	mux.HandleFunc("/start-core", s.requireAuth(s.handleStartCore))
	mux.HandleFunc("/stop-core", s.requireAuth(s.handleStopCore))
	return mux
}

func (s *coreServiceSupervisor) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.isAuthorized(r) {
			writeServiceJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (s *coreServiceSupervisor) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	running, port, pid := s.workerStatusLocked()
	s.mu.Unlock()
	writeServiceJSON(w, http.StatusOK, serviceHealthResponse{
		OK:         true,
		CoreSHA256: s.workerSHA256,
		Version:    constants.Version,
		Running:    running,
		CorePort:   port,
		CorePID:    pid,
	})
}

func (s *coreServiceSupervisor) handleStartCore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req startCoreRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req); err != nil {
		writeServiceJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}
	if err := validateStartCoreRequest(req, s.controlPort); err != nil {
		writeServiceJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	pid, err := s.startWorker(req)
	if err != nil {
		writeServiceJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeServiceJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"pid":  pid,
		"port": req.Port,
	})
}

func (s *coreServiceSupervisor) handleStopCore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.stopWorker()
	writeServiceJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *coreServiceSupervisor) workerStatusLocked() (running bool, port int, pid int) {
	if s.worker == nil {
		return false, 0, 0
	}
	select {
	case <-s.worker.done:
		s.worker = nil
		return false, 0, 0
	default:
		if s.worker.cmd != nil && s.worker.cmd.Process != nil {
			pid = s.worker.cmd.Process.Pid
		}
		return true, s.worker.port, pid
	}
}

func (s *coreServiceSupervisor) startWorker(req startCoreRequest) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Stop any previous worker cleanly before spawning the new one.
	s.stopWorkerLocked()

	args := []string{
		fmt.Sprintf("-home_dir=%s", filepath.Clean(req.HomeDir)),
		fmt.Sprintf("-port=%d", req.Port),
		fmt.Sprintf("-secret=%s", req.Secret),
	}
	if req.UserSID != "" {
		args = append(args, fmt.Sprintf("-user_sid=%s", req.UserSID))
	}

	cmd := exec.Command(s.workerBinaryPath, args...)
	cmd.Dir = filepath.Dir(s.workerBinaryPath)
	if s.configureCmd != nil {
		s.configureCmd(cmd)
	}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start worker: %w", err)
	}

	w := &managedWorker{
		cmd:    cmd,
		port:   req.Port,
		secret: req.Secret,
		done:   make(chan struct{}),
	}
	s.worker = w

	go func(mw *managedWorker) {
		_ = mw.cmd.Wait()
		close(mw.done)
	}(w)

	return cmd.Process.Pid, nil
}

func (s *coreServiceSupervisor) stopWorker() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopWorkerLocked()
}

func (s *coreServiceSupervisor) stopWorkerLocked() {
	w := s.worker
	if w == nil {
		return
	}
	s.worker = nil

	select {
	case <-w.done:
		return
	default:
	}

	// Ask the worker to tear down TUN/WFP/sysproxy cleanly via /manager/exit.
	if w.port > 0 && w.secret != "" {
		client := &http.Client{Timeout: 3 * time.Second}
		req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/manager/exit", w.port), nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+w.secret)
			resp, err := client.Do(req)
			if err == nil {
				_ = resp.Body.Close()
			}
		}
	}

	// Wait up to 4 seconds for clean exit before force-killing.
	select {
	case <-w.done:
		return
	case <-time.After(4 * time.Second):
	}

	if w.cmd != nil && w.cmd.Process != nil {
		_ = w.cmd.Process.Kill()
	}
	select {
	case <-w.done:
	case <-time.After(2 * time.Second):
	}
}

func writeServiceJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func bindServiceListener(preferredPort int) (net.Listener, int, error) {
	if preferredPort > 0 {
		if ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", preferredPort)); err == nil {
			return ln, preferredPort, nil
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}
	addr := ln.Addr().(*net.TCPAddr)
	return ln, addr.Port, nil
}

func writeServiceMetadataAtomic(metaPath string, meta serviceMetadata) error {
	if err := os.MkdirAll(filepath.Dir(metaPath), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := metaPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, metaPath)
}

func runServiceHTTPServer(ctx context.Context, sup *coreServiceSupervisor, ln net.Listener) {
	srv := &http.Server{
		Handler:           sup.handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	_ = srv.Serve(ln)
}
