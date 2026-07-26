package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSkipUsesDocumentedFlagsAndStrictJSON(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(tokenFile, []byte("admin-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/skip" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer admin-secret" {
			t.Fatalf("authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("content type = %q", got)
		}
		var got map[string]string
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"name": "claude", "message_id": "msg_1", "reason": "poison payload"}
		if got["name"] != want["name"] || got["message_id"] != want["message_id"] || got["reason"] != want["reason"] {
			t.Fatalf("body = %#v, want %#v", got, want)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	var stdout, stderr bytes.Buffer
	err := execute(context.Background(), []string{
		"skip", "--server", ts.URL, "--admin-token-file", tokenFile,
		"--name", "claude", "--message-id", "msg_1", "--reason", "poison payload",
	}, &stdout, &stderr, ts.Client())
	if err != nil {
		t.Fatalf("execute: %v (stderr %q)", err, stderr.String())
	}
}

func TestUISessionUsesAdminCredentialWithoutPrintingIt(t *testing.T) {
	adminFile := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(adminFile, []byte("UI_ADMIN_SECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/ui/bootstrap" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer UI_ADMIN_SECRET" {
			t.Fatalf("authorization = %q", got)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 0 {
			t.Fatalf("bootstrap body = %#v err=%v", body, err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"code": "ABCDEFGHJKMNPQRSTVWXYZ2345", "expires_at": expiresAt,
		})
	}))
	defer ts.Close()

	var stdout, stderr bytes.Buffer
	err := execute(context.Background(), []string{
		"ui-session", "--server", ts.URL, "--admin-token-file", adminFile,
	}, &stdout, &stderr, ts.Client())
	if err != nil {
		t.Fatalf("execute: %v (stderr %q)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ABCDEFGHJKMNPQRSTVWXYZ2345") ||
		!strings.Contains(stdout.String(), expiresAt) {
		t.Fatalf("stdout omitted login code or expiry: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "UI_ADMIN_SECRET") || strings.Contains(stderr.String(), "UI_ADMIN_SECRET") {
		t.Fatal("ui-session printed the administrator credential")
	}
}

func TestSendCarriesStructuredPayloadAndPrintsMessage(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "agent.token")
	if err := os.WriteFile(tokenFile, []byte("agent-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/send" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer agent-secret" {
			t.Fatalf("authorization = %q", got)
		}
		var got struct {
			From            string          `json:"from"`
			To              string          `json:"to"`
			Body            string          `json:"body"`
			Data            json.RawMessage `json:"data"`
			ReplyTo         string          `json:"reply_to"`
			ClientMessageID string          `json:"client_message_id"`
			AllowNew        bool            `json:"allow_new"`
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.From != "codex" || got.To != "claude" || got.Body != "review this" ||
			got.ReplyTo != "msg_parent" || got.ClientMessageID != "cli-1" || !got.AllowNew ||
			string(got.Data) != `{"priority":2}` {
			t.Fatalf("unexpected send body: %+v data=%s", got, got.Data)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message_id":"msg_1","seq":1}`))
	}))
	defer ts.Close()

	var stdout, stderr bytes.Buffer
	err := execute(context.Background(), []string{
		"send", "--server", ts.URL, "--token-file", tokenFile, "--from", "codex",
		"--to", "claude", "--body", "review this", "--data", `{"priority":2}`,
		"--reply-to", "msg_parent", "--client-message-id", "cli-1", "--allow-new",
	}, &stdout, &stderr, ts.Client())
	if err != nil {
		t.Fatalf("execute: %v (stderr %q)", err, stderr.String())
	}
	if got := stdout.String(); got != "{\"message_id\":\"msg_1\",\"seq\":1}\n" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestSendRejectsInvalidDataBeforeNetwork(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid --data must fail before network")
		return nil, nil
	})}
	var stdout, stderr bytes.Buffer
	err := execute(context.Background(), []string{
		"send", "--server", "https://agents.example.com", "--from", "codex",
		"--to", "claude", "--client-message-id", "bad-data", "--data", `{broken`,
	}, &stdout, &stderr, client)
	if err == nil || !strings.Contains(err.Error(), "valid JSON") {
		t.Fatalf("error = %v", err)
	}
}

func TestAckUsesAgentCredentialAndDeliveryID(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "agent.token")
	if err := os.WriteFile(tokenFile, []byte("agent-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/ack" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer agent-secret" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("headers = %#v", r.Header)
		}
		var got map[string]string
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got["name"] != "claude" || got["delivery_id"] != "dlv_1" {
			t.Fatalf("body = %#v", got)
		}
		w.Write([]byte(`{"acked":true,"delivery_id":"dlv_1"}`))
	}))
	defer ts.Close()

	var stdout, stderr bytes.Buffer
	err := execute(context.Background(), []string{
		"ack", "--server", ts.URL, "--token-file", tokenFile,
		"--name", "claude", "--delivery-id", "dlv_1",
	}, &stdout, &stderr, ts.Client())
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if stdout.String() != "{\"acked\":true,\"delivery_id\":\"dlv_1\"}\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRosterUsesAgentTokenAndPrintsJSON(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "agent.token")
	if err := os.WriteFile(tokenFile, []byte("agent-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/roster" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer agent-secret" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		w.Write([]byte(`[{"name":"claude","waiting":true}]`))
	}))
	defer ts.Close()

	var stdout, stderr bytes.Buffer
	if err := execute(context.Background(), []string{
		"roster", "--server", ts.URL, "--token-file", tokenFile,
	}, &stdout, &stderr, ts.Client()); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "[{\"name\":\"claude\",\"waiting\":true}]\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWaitRetriesTransientFailureAndPrintsValidatedDelivery(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.Path != "/wait" || r.URL.Query().Get("name") != "claude" {
			t.Fatalf("request = %s %s", r.Method, r.URL.String())
		}
		if _, ok := r.Context().Deadline(); !ok {
			t.Fatal("wait poll has no client-side deadline")
		}
		switch calls.Add(1) {
		case 1:
			return nil, errors.New("daemon restarting")
		case 2:
			return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		default:
			body := `{"delivery_id":"dlv_1","redelivery":false,"messages":[{"message_id":"msg_1"}]}`
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
	})}

	var stdout, stderr bytes.Buffer
	if err := execute(context.Background(), []string{
		"wait", "--server", "http://127.0.0.1:7777", "--name", "claude", "--timeout", "20ms",
	}, &stdout, &stderr, client); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d", calls.Load())
	}
	want := "{\"delivery_id\":\"dlv_1\",\"redelivery\":false,\"messages\":[{\"message_id\":\"msg_1\"}]}\n"
	if stdout.String() != want {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestWaitRejectsMalformedOrEmptyDelivery(t *testing.T) {
	for _, body := range []string{
		`not-json`,
		`{"delivery_id":"","messages":[]}`,
		`{"delivery_id":"dlv_1","messages":[{}]}`,
		`{"delivery_id":"dlv_1","messages":[]} trailing`,
	} {
		t.Run(body, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(body))
			}))
			defer ts.Close()

			var stdout, stderr bytes.Buffer
			err := execute(context.Background(), []string{
				"wait", "--server", ts.URL, "--name", "claude", "--timeout", "20ms",
			}, &stdout, &stderr, ts.Client())
			if err == nil {
				t.Fatalf("body %q must fail", body)
			}
			if stdout.Len() != 0 {
				t.Fatalf("invalid delivery printed: %q", stdout.String())
			}
		})
	}
}

func TestWaitHonorsRetryAfterFor429AndAbortsOther4xx(t *testing.T) {
	t.Run("retry-after", func(t *testing.T) {
		var calls atomic.Int32
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) == 1 {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.Write([]byte(`{"delivery_id":"dlv_1","messages":[{"message_id":"msg_1"}]}`))
		}))
		defer ts.Close()

		started := time.Now()
		var stdout, stderr bytes.Buffer
		if err := execute(context.Background(), []string{
			"wait", "--server", ts.URL, "--name", "claude", "--timeout", "20ms",
		}, &stdout, &stderr, ts.Client()); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(started); elapsed < 900*time.Millisecond {
			t.Fatalf("Retry-After ignored; elapsed %s", elapsed)
		}
	})

	t.Run("other client error", func(t *testing.T) {
		var calls atomic.Int32
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusConflict)
		}))
		defer ts.Close()

		var stdout, stderr bytes.Buffer
		err := execute(context.Background(), []string{
			"wait", "--server", ts.URL, "--name", "claude", "--timeout", "20ms",
		}, &stdout, &stderr, ts.Client())
		if err == nil || calls.Load() != 1 {
			t.Fatalf("error = %v, calls = %d", err, calls.Load())
		}
	})
}

func TestMintWritesSecretOnceToProtectedFileWithoutPrintingIt(t *testing.T) {
	dir := t.TempDir()
	adminFile := filepath.Join(dir, "admin.token")
	if err := os.WriteFile(adminFile, []byte("admin-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenOut := filepath.Join(dir, "athena.token")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/mint" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer admin-secret" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("headers = %#v", r.Header)
		}
		var got map[string]string
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got["name"] != "athena" {
			t.Fatalf("body = %#v", got)
		}
		w.Write([]byte(`{"name":"athena","token":"new-agent-secret"}`))
	}))
	defer ts.Close()

	var stdout, stderr bytes.Buffer
	if err := execute(context.Background(), []string{
		"mint", "--server", ts.URL, "--admin-token-file", adminFile,
		"--name", "athena", "--token-out", tokenOut,
	}, &stdout, &stderr, ts.Client()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "new-agent-secret") {
		t.Fatalf("secret printed to stdout: %q", stdout.String())
	}
	secret, err := os.ReadFile(tokenOut)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "new-agent-secret\n" {
		t.Fatalf("token file = %q", secret)
	}
	info, err := os.Stat(tokenOut)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("token mode = %o", got)
	}
}

func TestRetireRequiresAndSendsAuditReason(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/retire" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("request = %s %s headers=%#v", r.Method, r.URL.Path, r.Header)
		}
		var got map[string]string
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got["name"] != "solane" || got["reason"] != "agent decommissioned" {
			t.Fatalf("body = %#v", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	var stdout, stderr bytes.Buffer
	if err := execute(context.Background(), []string{
		"retire", "--server", ts.URL, "--name", "solane", "--reason", "agent decommissioned",
	}, &stdout, &stderr, ts.Client()); err != nil {
		t.Fatal(err)
	}
}

func TestPruneSendsExplicitRFC3339CutoffAndPrintsCounts(t *testing.T) {
	const cutoff = "2026-06-19T12:30:00Z"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/prune" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		var got map[string]string
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got["before"] != cutoff {
			t.Fatalf("before = %q", got["before"])
		}
		w.Write([]byte(`{"messages":2,"receipts":3,"deliveries":1}`))
	}))
	defer ts.Close()

	var stdout, stderr bytes.Buffer
	if err := execute(context.Background(), []string{
		"prune", "--server", ts.URL, "--before", cutoff,
	}, &stdout, &stderr, ts.Client()); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "{\"messages\":2,\"receipts\":3,\"deliveries\":1}\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestPruneSupportsRetentionAndRejectsTwoCutoffs(t *testing.T) {
	now := time.Now().UTC()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got map[string]string
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		cutoff, err := time.Parse(time.RFC3339Nano, got["before"])
		if err != nil {
			t.Fatal(err)
		}
		want := now.Add(-48 * time.Hour)
		if delta := cutoff.Sub(want); delta < -2*time.Second || delta > 2*time.Second {
			t.Fatalf("cutoff = %s, want approximately %s", cutoff, want)
		}
		w.Write([]byte(`{"messages":0,"receipts":0,"deliveries":0}`))
	}))
	defer ts.Close()

	var stdout, stderr bytes.Buffer
	if err := execute(context.Background(), []string{
		"prune", "--server", ts.URL, "--retention", "48h",
	}, &stdout, &stderr, ts.Client()); err != nil {
		t.Fatal(err)
	}

	err := execute(context.Background(), []string{
		"prune", "--server", ts.URL, "--retention", "48h", "--before", "2026-01-01T00:00:00Z",
	}, &stdout, &stderr, ts.Client())
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("conflicting cutoffs error = %v", err)
	}
}

func TestAdminInspectionCommandsUseCredentialFileAndPrintBoundedJSON(t *testing.T) {
	adminFile := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(adminFile, []byte("admin-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		command string
		body    string
	}{
		{command: "backlog", body: `{"pending_receipts":1,"mailboxes":[]}`},
		{command: "activity", body: `{"messages_sent":1,"mailboxes":[]}`},
		{command: "audit", body: `[{"action":"mint","mailbox_name":"athena"}]`},
	} {
		t.Run(tc.command, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/"+tc.command {
					t.Fatalf("request = %s %s", r.Method, r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer admin-secret" {
					t.Fatalf("authorization = %q", got)
				}
				w.Write([]byte(tc.body))
			}))
			defer ts.Close()

			var stdout, stderr bytes.Buffer
			if err := execute(context.Background(), []string{
				tc.command, "--server", ts.URL, "--admin-token-file", adminFile,
			}, &stdout, &stderr, ts.Client()); err != nil {
				t.Fatal(err)
			}
			if stdout.String() != tc.body+"\n" {
				t.Fatalf("stdout = %q", stdout.String())
			}
		})
	}
}

func TestReadTokenFileAcceptsProtectedSystemdCredentialOnly(t *testing.T) {
	credentialDir := filepath.Join(t.TempDir(), "credentials")
	if err := os.Mkdir(credentialDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(credentialDir, "admin-token")
	if err := os.WriteFile(path, []byte("systemd-secret\n"), 0o600); err != nil {
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
	if got, err := readTokenFile(path); err != nil || got != "systemd-secret" {
		t.Fatalf("systemd credential: got %q, err %v", got, err)
	}

	outside := filepath.Join(t.TempDir(), "admin-token")
	if err := os.WriteFile(outside, []byte("ordinary-secret\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if _, err := readTokenFile(outside); err == nil {
		t.Fatal("ordinary group-readable credential must remain rejected")
	}
}

func TestAuditCommandForwardsPagination(t *testing.T) {
	adminFile := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(adminFile, []byte("admin-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("after_id"); got != "41" {
			t.Fatalf("after_id = %q", got)
		}
		if got := r.URL.Query().Get("limit"); got != "7" {
			t.Fatalf("limit = %q", got)
		}
		w.Write([]byte(`[]`))
	}))
	defer ts.Close()
	var stdout, stderr bytes.Buffer
	if err := execute(context.Background(), []string{
		"audit", "--server", ts.URL, "--admin-token-file", adminFile,
		"--after-id", "41", "--limit", "7",
	}, &stdout, &stderr, ts.Client()); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "[]\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestCLIRejectsPlainHTTPToRemoteHost(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("insecure remote request must not be sent")
		return nil, nil
	})}
	var stdout, stderr bytes.Buffer
	err := execute(context.Background(), []string{
		"send", "--server", "http://agents.example.com:7777", "--from", "codex",
		"--to", "claude", "--client-message-id", "cli-remote-http",
	}, &stdout, &stderr, client)
	if err == nil || !strings.Contains(err.Error(), "plain HTTP") {
		t.Fatalf("error = %v", err)
	}
}

func TestCLIDoesNotFollowRedirectsWithBearerCredentials(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) != 1 {
			t.Fatal("redirect was followed")
		}
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"http://agents.example.com/steal"}},
			Body:       io.NopCloser(strings.NewReader("redirect")),
		}, nil
	})}
	var stdout, stderr bytes.Buffer
	err := execute(context.Background(), []string{
		"send", "--server", "https://bus.example.com", "--from", "codex",
		"--to", "claude", "--client-message-id", "no-redirect",
	}, &stdout, &stderr, client)
	if err == nil || calls.Load() != 1 {
		t.Fatalf("error = %v, calls = %d", err, calls.Load())
	}
}

func TestVersionPrintsReleaseIdentityWithoutNetwork(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("--version must not use the network")
		return nil, nil
	})}
	var stdout, stderr bytes.Buffer
	if err := execute(context.Background(), []string{"--version"}, &stdout, &stderr, client); err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); !strings.Contains(got, "agentbus dev") || !strings.Contains(got, "github.com/jahwag/agentbus") {
		t.Fatalf("version output = %q", got)
	}
}

func TestTopLevelHelpListsCompleteCommandSurface(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("--help must not use the network")
		return nil, nil
	})}
	var stdout, stderr bytes.Buffer
	if err := execute(context.Background(), []string{"--help"}, &stdout, &stderr, client); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"wait", "send", "ack", "roster", "mint", "skip", "retire", "prune", "backlog", "activity", "audit"} {
		if !strings.Contains(stdout.String(), command) {
			t.Fatalf("help omits %q: %s", command, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "AGENTBUS_ADMIN_TOKEN=") {
		t.Fatalf("help advertises literal admin secret: %s", stdout.String())
	}
}

func TestSubcommandsRejectUnexpectedPositionalArguments(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid command line must fail before network")
		return nil, nil
	})}
	var stdout, stderr bytes.Buffer
	err := execute(context.Background(), []string{
		"roster", "--server", "https://agents.example.com", "unexpected",
	}, &stdout, &stderr, client)
	if err == nil || !strings.Contains(err.Error(), "unexpected argument") {
		t.Fatalf("error = %v", err)
	}
}

func TestOneShotCommandsHaveClientDeadline(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 31*time.Second {
			t.Fatalf("request deadline = %v, present=%v", deadline, ok)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`[]`)),
			Header:     make(http.Header),
		}, nil
	})}
	var stdout, stderr bytes.Buffer
	if err := execute(context.Background(), []string{
		"roster", "--server", "https://agents.example.com",
	}, &stdout, &stderr, client); err != nil {
		t.Fatal(err)
	}
}

func TestCLIRejectsUnsafeTokenFilesBeforeNetwork(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsafe credential must fail before network")
		return nil, nil
	})}
	for _, tc := range []struct {
		name string
		body []byte
		mode os.FileMode
	}{
		{name: "world-readable", body: []byte("agent-secret"), mode: 0o644},
		{name: "oversized", body: bytes.Repeat([]byte("x"), 8193), mode: 0o600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.token")
			if err := os.WriteFile(path, tc.body, tc.mode); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			err := execute(context.Background(), []string{
				"send", "--server", "https://agents.example.com", "--token-file", path,
				"--to", "claude", "--client-message-id", "unsafe-token",
			}, &stdout, &stderr, client)
			if err == nil {
				t.Fatal("unsafe token file accepted")
			}
		})
	}
}

func TestCLIRejectsOversizedHTTPResponse(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), maxCLIResponseBytes+1))),
			Header:     make(http.Header),
		}, nil
	})}
	var stdout, stderr bytes.Buffer
	err := execute(context.Background(), []string{
		"roster", "--server", "https://agents.example.com",
	}, &stdout, &stderr, client)
	if err == nil || !strings.Contains(err.Error(), "512 KiB") {
		t.Fatalf("error = %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("oversized response printed: %d bytes", stdout.Len())
	}
}

func TestEnvironmentCompatibilityKeepsAgentVarsButIgnoresLiteralAdminSecret(t *testing.T) {
	t.Run("agent vars", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer env-agent-token" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["from"] != "codex" {
				t.Fatalf("from = %#v", body["from"])
			}
			w.Write([]byte(`{"message_id":"msg_env","seq":1}`))
		}))
		defer ts.Close()
		t.Setenv("AGENTBUS_SERVER", ts.URL)
		t.Setenv("AGENTBUS_NAME", "codex")
		t.Setenv("AGENTBUS_TOKEN", "env-agent-token")
		t.Setenv("AGENTBUS_TOKEN_FILE", "")

		var stdout, stderr bytes.Buffer
		if err := execute(context.Background(), []string{
			"send", "--to", "claude", "--client-message-id", "env-send",
		}, &stdout, &stderr, ts.Client()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("admin literal ignored", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "" {
				t.Fatalf("literal admin environment secret was used: %q", got)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()
		t.Setenv("AGENTBUS_ADMIN_TOKEN", "must-not-be-used")
		t.Setenv("AGENTBUS_ADMIN_TOKEN_FILE", "")

		var stdout, stderr bytes.Buffer
		if err := execute(context.Background(), []string{
			"retire", "--server", ts.URL, "--name", "old", "--reason", "done",
		}, &stdout, &stderr, ts.Client()); err != nil {
			t.Fatal(err)
		}
	})
}
