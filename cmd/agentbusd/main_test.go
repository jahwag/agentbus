package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jahwag/agentbus/internal/bus"
	"github.com/jahwag/agentbus/internal/httpapi"
	"github.com/jahwag/agentbus/internal/oidcauth"
)

type bearerRoundTripper struct {
	token string
	base  http.RoundTripper
	host  string
}

func (rt bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+rt.token)
	if rt.host != "" {
		clone.Host = rt.host
	}
	return rt.base.RoundTrip(clone)
}

func TestMCPRequiresAgentCredentialOnEveryRequest(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "bus.db")
	b, err := bus.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	agentToken, err := b.Mint("amara")
	if err != nil {
		t.Fatal(err)
	}
	const adminToken = "admin-secret-that-is-not-an-agent"
	const metadataURL = "https://agentbus.example.com/.well-known/oauth-protected-resource/mcp"
	h := mcpHandler(b, adminToken, nil, metadataURL)

	for name, tc := range map[string]struct {
		token string
		want  int
	}{
		"missing": {want: http.StatusUnauthorized},
		"admin":   {token: adminToken, want: http.StatusForbidden},
		"agent":   {token: agentToken, want: http.StatusUnsupportedMediaType},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("got %d, want %d", rec.Code, tc.want)
			}
			if name == "missing" &&
				!strings.Contains(rec.Header().Get("WWW-Authenticate"), `resource_metadata="`+metadataURL+`"`) {
				t.Fatalf("challenge omitted RFC 9728 metadata URL: %q", rec.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func TestOIDCOnlyMCPAllowsPublicHostWhileRESTRemainsLocal(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": "test-key",
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	issuer := jwksServer.URL + "/issuer"
	verifier := oidcauth.NewRemote(
		context.Background(),
		issuer,
		"agentbus-api",
		jwksServer.URL,
		"oid",
		"AgentBus.Agent",
	)
	dbPath := filepath.Join(t.TempDir(), "bus.db")
	b, err := bus.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.BindExternalIdentity("worker", "agent", issuer, "worker-oid"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token := signAgentBusTestJWT(t, key, map[string]any{
		"iss": issuer,
		"aud": "agentbus-api",
		"oid": "worker-oid",
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"roles": []string{
			"AgentBus.Agent",
		},
	})

	mux := http.NewServeMux()
	mux.Handle("/", (&httpapi.Server{Bus: b}).Handler())
	mux.Handle("/mcp", httpapi.ProtectLocalMode(
		mcpHandler(b, "", verifier, "https://agentbus.example.com/.well-known/oauth-protected-resource/mcp"),
		true,
	))
	ts := httptest.NewServer(mux)
	defer ts.Close()
	session, err := mcp.NewClient(
		&mcp.Implementation{Name: "oidc-e2e-test", Version: "0"},
		nil,
	).Connect(
		context.Background(),
		&mcp.StreamableClientTransport{
			Endpoint: ts.URL + "/mcp",
			HTTPClient: &http.Client{Transport: bearerRoundTripper{
				token: token,
				base:  http.DefaultTransport,
				host:  "agentbus.example.com",
			}},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(
		context.Background(),
		&mcp.CallToolParams{Name: "roster", Arguments: map[string]any{}},
	)
	if err != nil || result.IsError {
		t.Fatalf("OIDC official-SDK roster call = %+v, %v", result, err)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"worker"`)) {
		t.Fatalf("OIDC binding-derived roster omitted worker: %s", encoded)
	}

	request := func(path, bearer string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "https://agentbus.example.com"+path, nil)
		req.Host = "agentbus.example.com"
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	if got := request("/mcp", token).Code; got != http.StatusUnsupportedMediaType {
		t.Fatalf("valid OIDC request was blocked before MCP handling: got %d, want 415", got)
	}
	if got := request("/mcp", "").Code; got != http.StatusUnauthorized {
		t.Fatalf("missing OIDC token got %d, want 401", got)
	}
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rawDB.Exec(`DROP TABLE external_identities`); err != nil {
		rawDB.Close()
		t.Fatal(err)
	}
	rawDB.Close()
	if got := request("/mcp", token).Code; got != http.StatusInternalServerError {
		t.Fatalf("external identity storage failure got %d, want 500", got)
	}
	if got := request("/send", token).Code; got != http.StatusForbidden {
		t.Fatalf("OIDC-only mode exposed REST on a public Host: got %d, want 403", got)
	}
}

func signAgentBusTestJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{
		"alg": "RS256",
		"kid": "test-key",
		"typ": "JWT",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestHTTPServerBoundsConnectionsAroundLongPolls(t *testing.T) {
	srv := newHTTPServer("127.0.0.1:0", http.NewServeMux())
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("missing read/idle limits: %+v", srv)
	}
	if srv.WriteTimeout <= 290*time.Second {
		t.Fatalf("write timeout %s must exceed the longest wait", srv.WriteTimeout)
	}
	if srv.MaxHeaderBytes <= 0 || srv.MaxHeaderBytes > 32*1024 {
		t.Fatalf("MaxHeaderBytes=%d, want a positive limit up to 32 KiB", srv.MaxHeaderBytes)
	}
}

func TestLoadAdminTokenRequiresProtectedStrongFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(path, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAdminToken(path); err == nil {
		t.Fatal("weak admin token must be rejected")
	}
	const strong = "abm_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(path, []byte(strong+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAdminToken(path); err == nil {
		t.Fatal("group/world-readable admin token must be rejected")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadAdminToken(path)
	if err != nil || got != strong {
		t.Fatalf("protected strong token: got length %d, err %v", len(got), err)
	}
}

func TestLoadAdminTokenAcceptsProtectedSystemdCredential(t *testing.T) {
	credentialDir := filepath.Join(t.TempDir(), "credentials")
	if err := os.Mkdir(credentialDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const strong = "abm_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	path := filepath.Join(credentialDir, "admin-token")
	if err := os.WriteFile(path, []byte(strong+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(credentialDir, 0o550); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(credentialDir, 0o700) })
	t.Setenv("CREDENTIALS_DIRECTORY", credentialDir)
	got, err := loadAdminToken(path)
	if err != nil || got != strong {
		t.Fatalf("protected systemd credential: got length %d, err %v", len(got), err)
	}

	outside := filepath.Join(t.TempDir(), "admin-token")
	if err := os.WriteFile(outside, []byte(strong+"\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAdminToken(outside); err == nil {
		t.Fatal("ordinary group-readable file must remain rejected")
	}
}

func TestAuthenticatedStreamableMCPStampsIdentityPerRequest(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	workerToken, err := b.Mint("worker")
	if err != nil {
		t.Fatal(err)
	}
	leadToken, err := b.Mint("lead")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(mcpHandler(b, "admin-secret-that-is-not-an-agent", nil, ""))
	defer ts.Close()

	connect := func(token string) *mcp.ClientSession {
		t.Helper()
		transport := &mcp.StreamableClientTransport{
			Endpoint:   ts.URL,
			HTTPClient: &http.Client{Transport: bearerRoundTripper{token: token, base: http.DefaultTransport}},
		}
		session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).
			Connect(context.Background(), transport, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { session.Close() })
		return session
	}
	worker := connect(workerToken)
	lead := connect(leadToken)

	res, err := worker.CallTool(context.Background(), &mcp.CallToolParams{Name: "send", Arguments: map[string]any{
		"from": "lead", "to": "lead", "body": "credential wins", "client_message_id": "mcp-http-auth",
	}})
	if err != nil || res.IsError {
		t.Fatalf("send: %v %+v", err, res)
	}
	res, err = lead.CallTool(context.Background(), &mcp.CallToolParams{Name: "wait", Arguments: map[string]any{
		"name": "worker", "timeout_seconds": 1,
	}})
	if err != nil || res.IsError {
		t.Fatalf("wait: %v %+v", err, res)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out struct {
		Delivery struct {
			Messages []struct {
				From string `json:"from"`
			} `json:"messages"`
		} `json:"delivery"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Delivery.Messages) != 1 || out.Delivery.Messages[0].From != "worker" {
		t.Fatalf("credential identity was not stamped: %s", raw)
	}
	if _, err := b.Mint("worker"); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.CallTool(context.Background(), &mcp.CallToolParams{Name: "roster", Arguments: map[string]any{}}); err == nil {
		t.Fatal("rotated credential retained access through an existing MCP client")
	}
}

func TestStreamableMCPWaitRejectsCredentialRotatedWhileParked(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	oldWorkerToken, err := b.Mint("worker")
	if err != nil {
		t.Fatal(err)
	}
	leadToken, err := b.Mint("lead")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(mcpHandler(b, "admin-secret-that-is-not-an-agent", nil, ""))
	defer ts.Close()

	connect := func(token string) *mcp.ClientSession {
		t.Helper()
		transport := &mcp.StreamableClientTransport{
			Endpoint:   ts.URL,
			HTTPClient: &http.Client{Transport: bearerRoundTripper{token: token, base: http.DefaultTransport}},
		}
		session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).
			Connect(context.Background(), transport, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { session.Close() })
		return session
	}
	oldWorker := connect(oldWorkerToken)
	lead := connect(leadToken)

	type callResult struct {
		result *mcp.CallToolResult
		err    error
	}
	waited := make(chan callResult, 1)
	go func() {
		res, err := oldWorker.CallTool(context.Background(), &mcp.CallToolParams{
			Name: "wait", Arguments: map[string]any{"name": "worker", "timeout_seconds": 10},
		})
		waited <- callResult{result: res, err: err}
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		roster, err := b.Roster()
		if err != nil {
			t.Fatal(err)
		}
		parked := false
		for _, entry := range roster {
			if entry.Name == "worker" && entry.Waiting {
				parked = true
				break
			}
		}
		if parked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker MCP wait did not park")
		}
		time.Sleep(time.Millisecond)
	}

	newWorkerToken, err := b.Mint("worker")
	if err != nil {
		t.Fatal(err)
	}
	const marker = "must-not-cross-rotated-mcp-wait"
	res, err := lead.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "send", Arguments: map[string]any{
			"from": "lead", "to": "worker", "body": marker, "client_message_id": "parked-rotation",
		},
	})
	if err != nil || res.IsError {
		t.Fatalf("send: %v %+v", err, res)
	}

	var old callResult
	select {
	case old = <-waited:
	case <-time.After(2 * time.Second):
		t.Fatal("rotated MCP wait did not return")
	}
	leaked, _ := json.Marshal(old.result)
	visible := fmt.Sprintf("%v %s", old.err, leaked)
	if old.err == nil && (old.result == nil || !old.result.IsError) {
		t.Fatalf("rotated MCP wait succeeded: %s", visible)
	}
	for _, secret := range []string{marker, "delivery_id", oldWorkerToken, newWorkerToken} {
		if strings.Contains(visible, secret) {
			t.Fatalf("rotated MCP wait leaked %q: %s", secret, visible)
		}
	}

	replacement := connect(newWorkerToken)
	res, err = replacement.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "wait", Arguments: map[string]any{"name": "worker", "timeout_seconds": 1},
	})
	if err != nil || res.IsError {
		t.Fatalf("replacement wait: %v %+v", err, res)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out struct {
		Delivery struct {
			Redelivery bool `json:"redelivery"`
			Messages   []struct {
				Body string `json:"body"`
			} `json:"messages"`
		} `json:"delivery"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Delivery.Redelivery || len(out.Delivery.Messages) != 1 || out.Delivery.Messages[0].Body != marker {
		t.Fatalf("replacement did not receive preserved redelivery: %s", raw)
	}
}

func TestNormalizePublicOrigin(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
		ok   bool
	}{
		{"", "", true},
		{" https://agentbus.example.com/ ", "https://agentbus.example.com", true},
		{"http://127.0.0.1:7777", "http://127.0.0.1:7777", true},
		{"http://agentbus.localhost:7777", "http://agentbus.localhost:7777", true},
		{"http://agentbus.example.com", "", false},
		{"https://agentbus.example.com/ui", "", false},
		{"https://user@example.test", "", false},
		{"javascript:alert(1)", "", false},
	} {
		got, err := normalizePublicOrigin(tc.raw)
		if tc.ok && (err != nil || got != tc.want) {
			t.Errorf("normalizePublicOrigin(%q) = %q, %v", tc.raw, got, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("normalizePublicOrigin(%q) unexpectedly succeeded with %q", tc.raw, got)
		}
	}
}

func TestNewUIBrowserOIDCRequiresCompleteExactConfiguration(t *testing.T) {
	for _, key := range []string{
		"AGENTBUS_UI_OIDC_ISSUER",
		"AGENTBUS_UI_OIDC_CLIENT_ID",
		"AGENTBUS_UI_OIDC_CLIENT_SECRET",
		"AGENTBUS_UI_OIDC_REDIRECT_URL",
		"AGENTBUS_UI_OIDC_SCOPES",
		"AGENTBUS_UI_OIDC_SUBJECT_CLAIM",
		"AGENTBUS_UI_OIDC_REQUIRED_ROLE",
	} {
		t.Setenv(key, "")
	}
	const publicOrigin = "https://agentbus.example.com"

	t.Setenv("AGENTBUS_UI_OIDC_ISSUER", "https://identity.example.com/tenant/v2.0")
	if _, err := newUIBrowserOIDC(context.Background(), publicOrigin); err == nil {
		t.Fatal("issuer without client ID unexpectedly accepted")
	}

	t.Setenv("AGENTBUS_UI_OIDC_CLIENT_ID", "agentbus-browser")
	t.Setenv("AGENTBUS_UI_OIDC_REDIRECT_URL", "https://attacker.example/callback")
	if _, err := newUIBrowserOIDC(context.Background(), publicOrigin); err == nil {
		t.Fatal("redirect outside public origin unexpectedly accepted")
	}
}

func TestNewUIBrowserOIDCUsesPublicOriginCallback(t *testing.T) {
	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                provider.URL,
			"authorization_endpoint":                provider.URL + "/authorize",
			"token_endpoint":                        provider.URL + "/token",
			"jwks_uri":                              provider.URL + "/keys",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer provider.Close()
	for _, key := range []string{
		"AGENTBUS_UI_OIDC_CLIENT_SECRET",
		"AGENTBUS_UI_OIDC_REDIRECT_URL",
		"AGENTBUS_UI_OIDC_SCOPES",
		"AGENTBUS_UI_OIDC_REQUIRED_ROLE",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("AGENTBUS_UI_OIDC_ISSUER", provider.URL)
	t.Setenv("AGENTBUS_UI_OIDC_CLIENT_ID", "agentbus-browser")
	t.Setenv("AGENTBUS_UI_OIDC_SUBJECT_CLAIM", "oid")
	const publicOrigin = "https://agentbus.example.com"
	oidcLogin, err := newUIBrowserOIDC(context.Background(), publicOrigin)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&httpapi.Server{
		Bus:            b,
		AdminToken:     "admin-secret",
		UIOIDC:         oidcLogin,
		UIPublicOrigin: publicOrigin,
	}).Handler())
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/auth/oidc/start", nil)
	req.Host = "agentbus.example.com"
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	response, err := (&http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := location.Query().Get("redirect_uri"); got != publicOrigin+"/ui/auth/oidc/callback" {
		t.Fatalf("redirect_uri = %q", got)
	}
}

func TestLoadOptionalSecretUsesProtectedFileAndRejectsAmbiguousSource(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "oidc-secret")
	if err := os.WriteFile(secretFile, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_SECRET", "")
	t.Setenv("TEST_SECRET_FILE", secretFile)
	secret, err := loadOptionalSecret("TEST_SECRET", "TEST_SECRET_FILE")
	if err != nil || secret != "file-secret" {
		t.Fatalf("file secret = %q, %v", secret, err)
	}
	t.Setenv("TEST_SECRET", "inline-secret")
	if _, err := loadOptionalSecret("TEST_SECRET", "TEST_SECRET_FILE"); err == nil {
		t.Fatal("inline and file secret sources unexpectedly accepted together")
	}
}

func TestNormalizeUILogoutURL(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
		ok   bool
	}{
		{"", "", true},
		{
			"https://agentbus.example.com/cdn-cgi/access/logout",
			"https://agentbus.example.com/cdn-cgi/access/logout",
			true,
		},
		{"http://agentbus.example.com/logout", "", false},
		{"https://user@agentbus.example.com/logout", "", false},
		{"https://agentbus.example.com/logout#fragment", "", false},
		{"javascript:alert(1)", "", false},
	} {
		got, err := normalizeUILogoutURL(tc.raw)
		if tc.ok && (err != nil || got != tc.want) {
			t.Errorf("normalizeUILogoutURL(%q) = %q, %v", tc.raw, got, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("normalizeUILogoutURL(%q) unexpectedly succeeded with %q", tc.raw, got)
		}
	}
}
