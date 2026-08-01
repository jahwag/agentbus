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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/jahwag/agentbus/internal/buildinfo"
	"github.com/jahwag/agentbus/internal/bus"
	"github.com/jahwag/agentbus/internal/credentialfile"
	"github.com/jahwag/agentbus/internal/httpapi"
	"github.com/jahwag/agentbus/internal/mcpapi"
	"github.com/jahwag/agentbus/internal/oidcauth"
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

	oidcIssuer := os.Getenv("AGENTBUS_OIDC_ISSUER")
	oidcAudience := os.Getenv("AGENTBUS_OIDC_AUDIENCE")
	var workloadVerifier *oidcauth.Verifier
	if oidcIssuer != "" || oidcAudience != "" {
		if oidcIssuer == "" || oidcAudience == "" {
			slog.Error("AGENTBUS_OIDC_ISSUER and AGENTBUS_OIDC_AUDIENCE must be set together")
			os.Exit(2)
		}
		workloadVerifier, err = oidcauth.New(
			context.Background(),
			oidcIssuer,
			oidcAudience,
			envOr("AGENTBUS_OIDC_SUBJECT_CLAIM", "sub"),
			os.Getenv("AGENTBUS_OIDC_REQUIRED_ROLE"),
		)
		if err != nil {
			slog.Error("OIDC discovery", "err", err)
			os.Exit(1)
		}
	}
	mcpAuthOn := authOn || workloadVerifier != nil
	if err := httpapi.GuardListen(*listen, mcpAuthOn); err != nil {
		slog.Error("startup refused", "err", err)
		os.Exit(1)
	}
	mcpResourceURI := envOr("AGENTBUS_MCP_RESOURCE_URI", "http://127.0.0.1:7777/mcp")
	mcpResourceMetadataURL := envOr(
		"AGENTBUS_MCP_RESOURCE_METADATA_URL",
		strings.TrimSuffix(mcpResourceURI, "/mcp")+"/.well-known/oauth-protected-resource/mcp",
	)

	var uiPublicOrigin, uiLogoutURL string
	var uiAssertionVerifier *oidcauth.Verifier
	var uiOIDC *httpapi.BrowserOIDC
	if *uiEnabled {
		uiPublicOrigin, err = normalizePublicOrigin(os.Getenv("AGENTBUS_UI_PUBLIC_ORIGIN"))
		if err != nil {
			slog.Error("invalid AGENTBUS_UI_PUBLIC_ORIGIN", "err", err)
			os.Exit(2)
		}
		uiLogoutURL, err = normalizeUILogoutURL(os.Getenv("AGENTBUS_UI_LOGOUT_URL"))
		if err != nil {
			slog.Error("invalid AGENTBUS_UI_LOGOUT_URL", "err", err)
			os.Exit(2)
		}
		uiAssertionVerifier, err = newUIAssertionVerifier(context.Background())
		if err != nil {
			slog.Error("UI assertion verifier", "err", err)
			os.Exit(1)
		}
		uiOIDC, err = newUIBrowserOIDC(context.Background(), uiPublicOrigin)
		if err != nil {
			slog.Error("UI browser OIDC", "err", err)
			os.Exit(1)
		}
	}
	api := &httpapi.Server{
		Bus: b, AdminToken: adminToken, DisableUI: !*uiEnabled,
		UIAssertionVerifier: uiAssertionVerifier,
		UIAssertionHeader:   envOr("AGENTBUS_UI_ASSERTION_HEADER", "Cf-Access-Jwt-Assertion"),
		UIOIDC:              uiOIDC,
		UIPublicOrigin:      uiPublicOrigin,
		UILogoutURL:         uiLogoutURL,
	}
	mux := http.NewServeMux()
	mux.Handle("/", api.Handler())
	resourceMetadataChallenge := ""
	if workloadVerifier != nil {
		resourceMetadataChallenge = mcpResourceMetadataURL
	}
	mux.Handle("/mcp", httpapi.NoStore(httpapi.ProtectLocalMode(
		mcpHandler(b, adminToken, workloadVerifier, resourceMetadataChallenge),
		mcpAuthOn,
	)))
	if workloadVerifier != nil {
		mux.Handle("GET /.well-known/oauth-protected-resource/mcp", auth.ProtectedResourceMetadataHandler(
			&oauthex.ProtectedResourceMetadata{
				Resource:             mcpResourceURI,
				AuthorizationServers: []string{oidcIssuer},
				ScopesSupported:      strings.Fields(os.Getenv("AGENTBUS_OIDC_SCOPES")),
			},
		))
	}

	mode := "native-auth"
	if authOn && workloadVerifier != nil {
		mode = "native+oidc-auth"
	} else if workloadVerifier != nil {
		mode = "oidc-mcp-auth (REST remains loopback-only)"
	} else if !authOn {
		mode = "auth-off (INSECURE dev mode: loopback-only, identities are claims)"
	}
	uiMode := "unavailable without authentication"
	if !*uiEnabled {
		uiMode = "disabled"
	} else {
		var browserModes []string
		if authOn {
			browserModes = append(browserModes, "local-code")
		}
		if uiAssertionVerifier != nil {
			browserModes = append(browserModes, "trusted-edge")
		}
		if uiOIDC != nil {
			browserModes = append(browserModes, "native-oidc")
		}
		if len(browserModes) > 0 {
			uiMode = strings.Join(browserModes, "+")
		}
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
func mcpHandler(b *bus.Bus, adminToken string, workloadVerifier *oidcauth.Verifier, resourceMetadataURL string) http.Handler {
	h := mcpapi.Handler(b)
	if adminToken == "" && workloadVerifier == nil {
		return h
	}
	verifier := func(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		tokenHash := sha256.Sum256([]byte(token))
		adminHash := sha256.Sum256([]byte(adminToken))
		if adminToken != "" && subtle.ConstantTimeCompare(tokenHash[:], adminHash[:]) == 1 {
			return &auth.TokenInfo{Scopes: []string{"admin"}}, nil
		}
		principal, err := b.AuthenticatePrincipal(token)
		if err == nil {
			if principal.Kind != "agent" {
				return nil, fmt.Errorf("%w: operator credentials cannot use agent tools", auth.ErrInvalidToken)
			}
			return &auth.TokenInfo{
				Scopes: []string{"agent"},
				UserID: principal.Name,
				Extra: map[string]any{
					"agent":                 principal.Name,
					"credential_generation": principal.Generation,
					"principal":             principal,
				},
			}, nil
		}
		if !errors.Is(err, bus.ErrBadToken) {
			slog.Error("MCP credential verification failed", "err", err)
			return nil, errors.New("credential verifier unavailable")
		}
		if workloadVerifier == nil {
			return nil, fmt.Errorf("%w: invalid agent credential", auth.ErrInvalidToken)
		}
		assertion, err := workloadVerifier.Verify(ctx, token)
		if errors.Is(err, oidcauth.ErrVerifierUnavailable) {
			slog.Error("MCP workload verifier unavailable", "err", err)
			return nil, errors.New("credential verifier unavailable")
		}
		if err != nil {
			return nil, fmt.Errorf("%w: invalid workload credential", auth.ErrInvalidToken)
		}
		principal, err = b.AuthenticateExternal(assertion.Issuer, assertion.Subject, assertion.ExpiresAt)
		if errors.Is(err, bus.ErrBadToken) || (err == nil && principal.Kind != "agent") {
			return nil, fmt.Errorf("%w: workload identity is not an active agent", auth.ErrInvalidToken)
		}
		if err != nil {
			slog.Error("MCP external identity lookup failed", "err", err)
			return nil, errors.New("credential verifier unavailable")
		}
		return &auth.TokenInfo{
			Scopes:     append([]string{"agent"}, assertion.Scopes...),
			Expiration: assertion.ExpiresAt,
			UserID:     principal.Name,
			Extra: map[string]any{
				"agent":                 principal.Name,
				"credential_generation": principal.Generation,
				"principal":             principal,
			},
		}, nil
	}
	return auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{
		Scopes:                 []string{"agent"},
		ResourceMetadataURL:    resourceMetadataURL,
		AllowMissingExpiration: true,
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

func newUIAssertionVerifier(ctx context.Context) (*oidcauth.Verifier, error) {
	issuer := strings.TrimSuffix(strings.TrimSpace(os.Getenv("AGENTBUS_UI_ASSERTION_ISSUER")), "/")
	audience := strings.TrimSpace(os.Getenv("AGENTBUS_UI_ASSERTION_AUDIENCE"))
	jwksURL := strings.TrimSpace(os.Getenv("AGENTBUS_UI_ASSERTION_JWKS_URL"))
	if issuer == "" && audience == "" && jwksURL == "" {
		return nil, nil
	}
	if issuer == "" || audience == "" {
		return nil, errors.New("AGENTBUS_UI_ASSERTION_ISSUER and AGENTBUS_UI_ASSERTION_AUDIENCE must be set together")
	}
	subjectClaim := envOr("AGENTBUS_UI_ASSERTION_SUBJECT_CLAIM", "sub")
	requiredRole := os.Getenv("AGENTBUS_UI_ASSERTION_REQUIRED_ROLE")
	if jwksURL != "" {
		return oidcauth.NewRemote(ctx, issuer, audience, jwksURL, subjectClaim, requiredRole), nil
	}
	return oidcauth.New(ctx, issuer, audience, subjectClaim, requiredRole)
}

func newUIBrowserOIDC(ctx context.Context, publicOrigin string) (*httpapi.BrowserOIDC, error) {
	issuer := strings.TrimSpace(os.Getenv("AGENTBUS_UI_OIDC_ISSUER"))
	clientID := strings.TrimSpace(os.Getenv("AGENTBUS_UI_OIDC_CLIENT_ID"))
	if issuer == "" && clientID == "" {
		return nil, nil
	}
	if issuer == "" || clientID == "" {
		return nil, errors.New("AGENTBUS_UI_OIDC_ISSUER and AGENTBUS_UI_OIDC_CLIENT_ID must be set together")
	}
	expectedRedirectURL := ""
	if publicOrigin != "" {
		expectedRedirectURL = strings.TrimSuffix(publicOrigin, "/") + "/ui/auth/oidc/callback"
	}
	redirectURL := strings.TrimSpace(os.Getenv("AGENTBUS_UI_OIDC_REDIRECT_URL"))
	if redirectURL == "" {
		redirectURL = expectedRedirectURL
	}
	if expectedRedirectURL != "" && redirectURL != expectedRedirectURL {
		return nil, errors.New("AGENTBUS_UI_OIDC_REDIRECT_URL must match AGENTBUS_UI_PUBLIC_ORIGIN callback")
	}
	clientSecret, err := loadOptionalSecret("AGENTBUS_UI_OIDC_CLIENT_SECRET", "AGENTBUS_UI_OIDC_CLIENT_SECRET_FILE")
	if err != nil {
		return nil, err
	}
	return httpapi.NewBrowserOIDC(ctx, httpapi.BrowserOIDCConfig{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       strings.Fields(os.Getenv("AGENTBUS_UI_OIDC_SCOPES")),
		SubjectClaim: envOr("AGENTBUS_UI_OIDC_SUBJECT_CLAIM", "sub"),
		RequiredRole: os.Getenv("AGENTBUS_UI_OIDC_REQUIRED_ROLE"),
	})
}

func loadOptionalSecret(valueEnv, fileEnv string) (string, error) {
	value := os.Getenv(valueEnv)
	path := strings.TrimSpace(os.Getenv(fileEnv))
	if value != "" && path != "" {
		return "", fmt.Errorf("%s and %s are mutually exclusive", valueEnv, fileEnv)
	}
	if path != "" {
		raw, err := credentialfile.Read(path, 8192)
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(string(raw))
	}
	if len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
		return "", fmt.Errorf("%s must be at most 4096 bytes without newlines", valueEnv)
	}
	return value, nil
}

func normalizePublicOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	origin, err := url.Parse(raw)
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") ||
		origin.Host == "" || origin.User != nil || origin.RawQuery != "" ||
		origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return "", errors.New("must be an absolute http(s) origin without a path, query, credentials, or fragment")
	}
	host := origin.Hostname()
	ip := net.ParseIP(host)
	if origin.Scheme != "https" && host != "localhost" && host != "agentbus.localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", errors.New("must use HTTPS except on loopback")
	}
	return origin.Scheme + "://" + origin.Host, nil
}

func normalizeUILogoutURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	logoutURL, err := url.Parse(raw)
	if err != nil || logoutURL.Scheme != "https" || logoutURL.Host == "" ||
		logoutURL.User != nil || logoutURL.Fragment != "" {
		return "", errors.New("must be an absolute HTTPS URL without credentials or a fragment")
	}
	return logoutURL.String(), nil
}
