// agentbusd is the AgentBus daemon: one process serving the plain HTTP API
// at / and the MCP Streamable HTTP endpoint at /mcp, over one SQLite store.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/jahwag/agentbus/internal/buildinfo"
	"github.com/jahwag/agentbus/internal/bus"
	"github.com/jahwag/agentbus/internal/credentialfile"
	"github.com/jahwag/agentbus/internal/httpapi"
	"github.com/jahwag/agentbus/internal/mcpapi"
)

func main() {
	syscall.Umask(0o077)
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(buildinfo.String())
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--healthcheck" {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(envOr("AGENTBUS_SERVER", "http://127.0.0.1:7777") + "/readyz")
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		resp.Body.Close()
		return
	}
	listen := flag.String("listen", "127.0.0.1:7777", "loopback listen address (use a TLS reverse proxy for remote access)")
	dbPath := flag.String("db", defaultDB(), "path to the SQLite store")
	adminTokenFile := flag.String("admin-token-file", os.Getenv("AGENTBUS_ADMIN_TOKEN_FILE"),
		"protected file enabling auth mode; systemd credentials are recommended")
	uiEnabled := flag.Bool("ui", true, "serve the authenticated operator dashboard on the daemon listener")
	flag.Parse()

	adminToken, err := loadAdminToken(*adminTokenFile)
	if err != nil {
		slog.Error("load admin credential", "err", err)
		os.Exit(1)
	}
	authOn := adminToken != ""
	if err := httpapi.GuardListen(*listen, authOn); err != nil {
		slog.Error("startup refused", "err", err)
		os.Exit(1)
	}
	if err := ensurePrivateDBDir(*dbPath); err != nil {
		slog.Error("db dir", "err", err)
		os.Exit(1)
	}
	b, err := bus.Open(*dbPath)
	if err != nil {
		slog.Error("open bus", "err", err)
		os.Exit(1)
	}
	defer b.Close()

	api := &httpapi.Server{Bus: b, AdminToken: adminToken, DisableUI: !*uiEnabled}
	mux := http.NewServeMux()
	mux.Handle("/", api.Handler())
	mux.Handle("/mcp", httpapi.NoStore(httpapi.ProtectLocalMode(mcpHandler(b, adminToken), authOn)))

	mode := "auth-on"
	if !authOn {
		mode = "auth-off (INSECURE dev mode: loopback-only, identities are claims)"
	}
	uiMode := "enabled"
	if !*uiEnabled {
		uiMode = "disabled"
	} else if !authOn {
		uiMode = "unavailable without authentication"
	}
	slog.Info("agentbus listening", "addr", *listen, "db", *dbPath, "mode", mode, "ui", uiMode)
	srv := newHTTPServer(*listen, logRequests(mux))
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("serve", "err", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("graceful shutdown", "err", err)
			if err := srv.Close(); err != nil {
				slog.Error("forced shutdown", "err", err)
			}
		}
	}
}

func ensurePrivateDBDir(dbPath string) error {
	dir := filepath.Dir(dbPath)
	if dir == "." {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("database parent must be a directory")
	}
	return os.Chmod(dir, 0o700)
}

func loadAdminToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	raw, err := credentialfile.Read(path, 4096)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if len(token) < 32 || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("admin credential must be 32-512 non-whitespace bytes")
	}
	return token, nil
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      310 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}
}

// mcpHandler verifies every authenticated request before the MCP protocol sees
// it. Agent identity is carried in SDK TokenInfo and resolved again by each
// tool call; the admin credential deliberately lacks the required agent scope.
func mcpHandler(b *bus.Bus, adminToken string) http.Handler {
	h := mcpapi.Handler(b)
	if adminToken == "" {
		return h
	}
	verifier := func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		tokenInfo := &auth.TokenInfo{Expiration: time.Now().Add(time.Hour)}
		tokenHash := sha256.Sum256([]byte(token))
		adminHash := sha256.Sum256([]byte(adminToken))
		if subtle.ConstantTimeCompare(tokenHash[:], adminHash[:]) == 1 {
			tokenInfo.Scopes = []string{"admin"}
			return tokenInfo, nil
		}
		principal, err := b.AuthenticatePrincipal(token)
		if err != nil {
			if errors.Is(err, bus.ErrBadToken) {
				return nil, fmt.Errorf("%w: invalid agent credential", auth.ErrInvalidToken)
			}
			slog.Error("MCP credential verification failed", "err", err)
			return nil, errors.New("credential verifier unavailable")
		}
		tokenInfo.Scopes = []string{"agent"}
		tokenInfo.Extra = map[string]any{
			"agent":                 principal.Name,
			"credential_generation": principal.Generation,
		}
		return tokenInfo, nil
	}
	return auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{
		Scopes: []string{"agent"},
	})(h)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" {
			slog.Info("request", "method", r.Method, "path", r.URL.Path,
				"status", recorder.status, "bytes", recorder.bytes,
				"duration_ms", time.Since(started).Milliseconds())
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func (w *statusRecorder) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}

func (w *statusRecorder) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func defaultDB() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "agentbus.db"
	}
	return filepath.Join(home, ".agentbus", "bus.db")
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
