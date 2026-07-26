package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jahwag/agentbus/internal/bus"
)

type bearerRoundTripper struct {
	token string
	base  http.RoundTripper
}

func (rt bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+rt.token)
	return rt.base.RoundTrip(clone)
}

func TestMCPRequiresAgentCredentialOnEveryRequest(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	agentToken, err := b.Mint("amara")
	if err != nil {
		t.Fatal(err)
	}
	const adminToken = "admin-secret-that-is-not-an-agent"
	h := mcpHandler(b, adminToken)

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
		})
	}
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
	ts := httptest.NewServer(mcpHandler(b, "admin-secret-that-is-not-an-agent"))
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
	ts := httptest.NewServer(mcpHandler(b, "admin-secret-that-is-not-an-agent"))
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
