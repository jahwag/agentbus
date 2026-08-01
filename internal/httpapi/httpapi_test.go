package httpapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jahwag/agentbus/internal/bus"
	"github.com/jahwag/agentbus/internal/oidcauth"
)

func server(t *testing.T) *httptest.Server {
	t.Helper()
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	ts := httptest.NewServer((&Server{Bus: b}).Handler())
	t.Cleanup(ts.Close)
	return ts
}

func post(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	buf, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func mintUICode(t *testing.T, serverURL, adminToken string) string {
	t.Helper()
	bootstrap, _ := http.NewRequest(http.MethodPost, serverURL+"/ui/bootstrap", bytes.NewBufferString(`{}`))
	bootstrap.Header.Set("Content-Type", "application/json")
	bootstrap.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	var minted struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&minted); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return minted.Code
}

func submitUILogin(t *testing.T, serverURL, code string, headers map[string]string) *http.Response {
	t.Helper()
	form := url.Values{"code": {code}}
	login, _ := http.NewRequest(http.MethodPost, serverURL+"/ui/login", strings.NewReader(form.Encode()))
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for name, value := range headers {
		login.Header.Set(name, value)
	}
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(login)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func loginUI(t *testing.T, serverURL, adminToken string) *http.Cookie {
	t.Helper()
	code := mintUICode(t, serverURL, adminToken)
	resp := submitUILogin(t, serverURL, code, map[string]string{"Origin": serverURL})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || len(resp.Cookies()) != 1 {
		t.Fatalf("UI login failed: status=%d cookies=%d", resp.StatusCode, len(resp.Cookies()))
	}
	return resp.Cookies()[0]
}

// Slice 8: send → wait → ack roundtrip over HTTP with distinct outcomes for
// timeout (204) and conflict (409); wait acknowledges nothing.
func TestHTTPRoundtrip(t *testing.T) {
	ts := server(t)

	resp := post(t, ts.URL+"/send", map[string]any{
		"from": "codex", "to": "claude", "body": "hello",
		"data": map[string]any{"pr": 42}, "client_message_id": "http-roundtrip", "allow_new": true,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send: %d", resp.StatusCode)
	}

	resp, err := http.Get(ts.URL + "/wait?name=claude&timeout=2")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("wait: %v %d", err, resp.StatusCode)
	}
	var d bus.Delivery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(d.Messages) != 1 || d.Messages[0].Body != "hello" || string(d.Messages[0].Data) != `{"pr":42}` {
		t.Fatalf("wrong delivery: %+v", d)
	}

	// wait acknowledged nothing: same delivery again
	resp, _ = http.Get(ts.URL + "/wait?name=claude&timeout=2")
	var d2 bus.Delivery
	json.NewDecoder(resp.Body).Decode(&d2)
	resp.Body.Close()
	if d2.ID != d.ID || !d2.Redelivery {
		t.Fatalf("wait must be read-only, got %+v", d2)
	}

	if resp = post(t, ts.URL+"/ack", map[string]string{"name": "claude", "delivery_id": "dlv_forged"}); resp.StatusCode != http.StatusConflict {
		t.Fatalf("forged ack: %d, want 409", resp.StatusCode)
	}
	if resp = post(t, ts.URL+"/ack", map[string]string{"name": "claude", "delivery_id": d.ID}); resp.StatusCode != http.StatusOK {
		t.Fatalf("ack: %d", resp.StatusCode)
	}

	resp, _ = http.Get(ts.URL + "/wait?name=claude&timeout=0.05")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("empty wait must 204, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	if resp = post(t, ts.URL+"/send", map[string]any{"from": "codex", "to": "ghost", "body": "x", "client_message_id": "http-unknown"}); resp.StatusCode != http.StatusConflict {
		t.Fatalf("unknown recipient: %d, want 409", resp.StatusCode)
	}

	resp, _ = http.Get(ts.URL + "/roster")
	var roster []bus.RosterEntry
	json.NewDecoder(resp.Body).Decode(&roster)
	resp.Body.Close()
	if len(roster) != 2 { // codex and claude
		t.Fatalf("roster: %+v", roster)
	}

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %v %d", path, err, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

// Slice 10: with auth enabled, requests need a bearer token, identity derives
// from the credential (a lied "from" is overridden), and admin ops reject
// agent tokens.
func TestAuthDerivedIdentity(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	t.Cleanup(ts.Close)

	do := func(method, path, token string, body any) *http.Response {
		t.Helper()
		buf, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader(buf))
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	if resp := do("POST", "/send", "", map[string]any{"to": "x", "body": "x"}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token must 401, got %d", resp.StatusCode)
	}

	resp := do("POST", "/mint", "admin-secret", map[string]string{"name": "worker-1"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mint: %d", resp.StatusCode)
	}
	var minted struct{ Token string }
	json.NewDecoder(resp.Body).Decode(&minted)

	resp = do("POST", "/mint", "admin-secret", map[string]string{"name": "lead"})
	var lead struct{ Token string }
	json.NewDecoder(resp.Body).Decode(&lead)

	if resp := do("POST", "/send", "admin-secret", map[string]any{
		"from": "lead", "to": "worker-1", "body": "forged", "client_message_id": "admin-forge",
	}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin token must not act as an agent, got %d", resp.StatusCode)
	}
	if resp := do("GET", "/wait?name=lead&timeout=0.01", "admin-secret", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin token must not consume an inbox, got %d", resp.StatusCode)
	}
	if resp := do("POST", "/ack", "admin-secret", map[string]string{
		"name": "lead", "delivery_id": "dlv_forged",
	}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin token must not ack agent mail, got %d", resp.StatusCode)
	}

	// worker-1 lies about being the lead; the credential wins.
	if resp := do("POST", "/send", minted.Token, map[string]any{
		"from": "lead", "to": "lead", "body": "impersonation attempt", "client_message_id": "auth-derived",
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("send: %d", resp.StatusCode)
	}
	resp = do("GET", "/wait?name=worker-1&timeout=2", lead.Token, nil) // name param ignored too
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lead wait: %d", resp.StatusCode)
	}
	var d bus.Delivery
	json.NewDecoder(resp.Body).Decode(&d)
	if len(d.Messages) != 1 || d.Messages[0].From != "worker-1" {
		t.Fatalf("sender must be stamped from the credential, got %+v", d.Messages)
	}

	if resp := do("POST", "/mint", minted.Token, map[string]string{"name": "evil"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("agent token on admin op must 403, got %d", resp.StatusCode)
	}
	if resp := do("POST", "/retire", minted.Token, map[string]string{"name": "lead", "reason": "x"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("agent token on retire must 403, got %d", resp.StatusCode)
	}
}

func TestAdminCannotConvertAgentOrMintOperatorNativeCredential(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	token, err := b.Mint("human.alex")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.BindExternalIdentity(
		"operator.alex",
		"operator",
		"https://edge.example",
		"operator-1",
	); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	t.Cleanup(ts.Close)

	post := func(path, body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer admin-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	resp := post(
		"/bind-identity",
		`{"name":"human.alex","kind":"operator","issuer":"https://edge.example","subject":"human-1"}`,
	)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("agent-to-operator conversion got %d, want 409", resp.StatusCode)
	}
	if _, err := b.AuthenticatePrincipal(token); err != nil {
		t.Fatalf("failed HTTP kind change revoked agent credential: %v", err)
	}
	resp = post("/mint", `{"name":"operator.alex"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("native operator mint got %d, want 400", resp.StatusCode)
	}
}

func TestHTTPWaitRejectsCredentialRotatedWhileParked(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	oldToken, err := b.Mint("worker")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Mint("lead"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	t.Cleanup(ts.Close)

	type result struct {
		resp *http.Response
		err  error
	}
	waited := make(chan result, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/wait?timeout=5", nil)
		req.Header.Set("Authorization", "Bearer "+oldToken)
		resp, err := http.DefaultClient.Do(req)
		waited <- result{resp: resp, err: err}
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		entries, err := b.Roster()
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) == 2 && entries[1].Name == "worker" && entries[1].Waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("old credential wait did not park")
		}
		time.Sleep(time.Millisecond)
	}

	newToken, err := b.Mint("worker")
	if err != nil {
		t.Fatal(err)
	}
	const marker = "must-not-cross-rotated-http-wait"
	if _, err := b.Send("lead", "worker", bus.SendOpts{Body: marker, ClientMessageID: "rotate-http"}); err != nil {
		t.Fatal(err)
	}

	got := <-waited
	if got.err != nil {
		t.Fatal(got.err)
	}
	defer got.resp.Body.Close()
	body, err := io.ReadAll(got.resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got.resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("rotated parked wait got %d and %s, want 401", got.resp.StatusCode, body)
	}
	for _, forbidden := range []string{marker, oldToken, newToken, "delivery_id"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("rotated credential response exposed %q: %s", forbidden, body)
		}
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/wait?timeout=1", nil)
	req.Header.Set("Authorization", "Bearer "+newToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("replacement credential wait got %d", resp.StatusCode)
	}
	var delivery bus.Delivery
	if err := json.NewDecoder(resp.Body).Decode(&delivery); err != nil {
		t.Fatal(err)
	}
	if len(delivery.Messages) != 1 || delivery.Messages[0].Body != marker || !delivery.Redelivery {
		t.Fatalf("replacement credential did not receive the preserved delivery: %+v", delivery)
	}
}

func TestHTTPSendRequiresIdempotencyKey(t *testing.T) {
	ts := server(t)
	resp := post(t, ts.URL+"/send", map[string]any{
		"from": "codex", "to": "claude", "body": "ambiguous", "allow_new": true,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing client_message_id: got %d, want 400", resp.StatusCode)
	}
}

func TestHTTPCursorsStayPrivate(t *testing.T) {
	ts := server(t)
	resp := post(t, ts.URL+"/send", map[string]any{
		"from": "codex", "to": "claude", "body": "private cursor",
		"client_message_id": "private-cursor", "allow_new": true,
	})
	resp.Body.Close()
	resp, err := http.Get(ts.URL + "/wait?name=claude&timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	var delivery map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&delivery); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, exposed := delivery["through"]; exposed {
		t.Fatalf("delivery exposed private watermark: %+v", delivery)
	}
	resp = post(t, ts.URL+"/ack", map[string]any{
		"name": "claude", "delivery_id": delivery["delivery_id"],
	})
	var ack map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		t.Fatal(err)
	}
	if ack["acked"] != true || ack["delivery_id"] != delivery["delivery_id"] {
		t.Fatalf("ack must confirm the opaque delivery, got %+v", ack)
	}
	if _, exposed := ack["cursor"]; exposed {
		t.Fatalf("ack exposed private cursor: %+v", ack)
	}
}

func TestHTTPWaitRejectsCursorAndUnknownParameters(t *testing.T) {
	ts := server(t)
	for _, query := range []string{"name=claude&cursor=99", "name=claude&tiemout=1"} {
		resp, err := http.Get(ts.URL + "/wait?" + query)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("query %q: got %d, want 400", query, resp.StatusCode)
		}
	}
}

func TestHTTPMutationRequiresOneStrictJSONObject(t *testing.T) {
	ts := server(t)
	for name, tc := range map[string]struct {
		contentType string
		body        string
		want        int
	}{
		"content type":   {"text/plain", `{"from":"codex"}`, http.StatusUnsupportedMediaType},
		"unknown field":  {"application/json", `{"from":"codex","to":"claude","body":"x","client_message_id":"strict-1","allow_new":true,"surprise":1}`, http.StatusBadRequest},
		"trailing value": {"application/json", `{"from":"codex","to":"claude","body":"x","client_message_id":"strict-2","allow_new":true}{}`, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := http.Post(ts.URL+"/send", tc.contentType, bytes.NewBufferString(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("got %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

func TestHTTPWaitRejectsNonFiniteTimeout(t *testing.T) {
	ts := server(t)
	for _, value := range []string{"NaN", "%2BInf", "-Inf"} {
		resp, err := http.Get(ts.URL + "/wait?name=claude&timeout=" + value)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("timeout %q: got %d, want 400", value, resp.StatusCode)
		}
	}
}

func TestAuthOffHandlerRejectsBrowserAndReboundHosts(t *testing.T) {
	ts := server(t)
	for name, mutate := range map[string]func(*http.Request){
		"browser origin": func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") },
		"rebound host":   func(r *http.Request) { r.Host = "attacker.example" },
	} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/roster", nil)
			if err != nil {
				t.Fatal(err)
			}
			mutate(req)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("got %d, want 403", resp.StatusCode)
			}
		})
	}
}

func TestHTTPResponsesAreNeverCacheable(t *testing.T) {
	ts := server(t)
	resp, err := http.Get(ts.URL + "/roster")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", got)
	}
}

func TestHTTPMapsResourceExhaustionForRetry(t *testing.T) {
	rec := httptest.NewRecorder()
	writeBusError(rec, bus.ErrWaiterLimit)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("resource exhaustion must tell clients when to retry")
	}
}

func TestHTTPDoesNotExposeInternalErrors(t *testing.T) {
	rec := httptest.NewRecorder()
	writeBusError(rec, errors.New("sqlite: /secret/path/bus.db is corrupt"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500", rec.Code)
	}
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["code"] != "internal_error" || strings.Contains(out["error"], "sqlite") || strings.Contains(out["error"], "/secret") {
		t.Fatalf("internal detail leaked: %+v", out)
	}
}

func TestHTTPAdminCanPruneSettledMail(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()

	_, err = b.Mint("claude")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Send("codex", "claude", bus.SendOpts{Body: "done", ClientMessageID: "http-prune"}); err != nil {
		t.Fatal(err)
	}
	d, err := b.NextDelivery("claude")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ack("claude", d.ID); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"before": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/prune", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("prune: got %d", resp.StatusCode)
	}
	var result bus.PruneResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Messages != 1 || result.Receipts != 1 {
		t.Fatalf("unexpected prune result: %+v", result)
	}
}

func TestHTTPAdminCanInspectBacklogAndAudit(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.Mint("amara"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Send("amara", "athena", bus.SendOpts{
		Body: "queued", ClientMessageID: "inspect-backlog", AllowNew: true,
	}); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()

	for _, path := range []string{"/backlog", "/audit"} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer admin-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: got %d", path, resp.StatusCode)
		}
	}
}

func TestHTTPActivityIsAdminOnlyAndBodyFree(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	agentToken, err := b.Mint("amara")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Send("amara", "athena", bus.SendOpts{
		Body: "HTTP_ACTIVITY_SECRET_BODY", ClientMessageID: "inspect-activity", AllowNew: true,
	}); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/activity", nil)
	req.Header.Set("Authorization", "Bearer "+agentToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("agent activity inspection status = %d, want 403", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/activity", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin activity inspection status = %d: %s", resp.StatusCode, raw)
	}
	if bytes.Contains(raw, []byte("HTTP_ACTIVITY_SECRET_BODY")) {
		t.Fatal("activity endpoint leaked a message body")
	}
	var report bus.ActivityReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.SinceTracking.MessagesSent != 1 || report.SinceTracking.ReceiptsEnqueued != 1 || len(report.Mailboxes) != 2 {
		t.Fatalf("wrong activity response: %+v", report)
	}
}

func TestUIBootstrapRequiresAdminAndReturnsShortLivedCode(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()

	request := func(token string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/ui/bootstrap", bytes.NewBufferString(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := request("")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated bootstrap status = %d, want 401", resp.StatusCode)
	}

	resp = request("admin-secret")
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin bootstrap status = %d: %s", resp.StatusCode, raw)
	}
	var minted struct {
		Code      string `json:"code"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &minted); err != nil {
		t.Fatal(err)
	}
	if len(minted.Code) < 20 || len(minted.Code) > 64 {
		t.Fatalf("bootstrap code length = %d, want bounded high-entropy code", len(minted.Code))
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, minted.ExpiresAt)
	if err != nil || time.Until(expiresAt) <= 0 || time.Until(expiresAt) > 2*time.Minute {
		t.Fatalf("invalid bootstrap expiry %q: %v", minted.ExpiresAt, err)
	}
	if bytes.Contains(raw, []byte("admin-secret")) {
		t.Fatal("bootstrap response exposed the admin bearer")
	}
}

func TestUIBootstrapCodeExpiresBeforeLogin(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	ts := httptest.NewServer((&Server{
		Bus: b, AdminToken: "admin-secret", uiNow: func() time.Time { return now },
	}).Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/bootstrap", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var minted struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&minted); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	now = now.Add(uiBootstrapTTL + time.Second)

	form := url.Values{"code": {minted.Code}}
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || len(resp.Cookies()) != 0 {
		t.Fatalf("expired code status/cookies = %d/%d", resp.StatusCode, len(resp.Cookies()))
	}
}

func TestUILoginConsumesCodeAndSetsRestrictedSessionCookie(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/bootstrap", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var minted struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&minted); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	login := func(code string) *http.Response {
		t.Helper()
		form := url.Values{"code": {code}}
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/ui/login", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", ts.URL)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp = login(minted.Code)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/ui/" {
		t.Fatalf("login status/location = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %d, want one", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != uiSessionCookie || cookie.Value == "" || !cookie.HttpOnly ||
		cookie.Path != "/ui" || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unsafe UI session cookie: %+v", cookie)
	}

	resp = login(minted.Code)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || len(resp.Cookies()) != 0 {
		t.Fatalf("reused code status/cookies = %d/%d, want 401/0", resp.StatusCode, len(resp.Cookies()))
	}
}

func TestUILoginAcceptsSameOriginFetchMetadataWhenBrowserOmitsOrigin(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()

	resp := submitUILogin(t, ts.URL, mintUICode(t, ts.URL, "admin-secret"), map[string]string{
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Dest": "document",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || len(resp.Cookies()) != 1 {
		t.Fatalf("same-origin browser login status/cookies = %d/%d", resp.StatusCode, len(resp.Cookies()))
	}
}

func TestUILoginAcceptsOpaqueOriginOnlyForSameOriginNavigation(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()

	resp := submitUILogin(t, ts.URL, mintUICode(t, ts.URL, "admin-secret"), map[string]string{
		"Origin":         "null",
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Dest": "document",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || len(resp.Cookies()) != 1 {
		t.Fatalf("opaque same-origin browser login status/cookies = %d/%d", resp.StatusCode, len(resp.Cookies()))
	}
}

func TestUILoginRejectsCrossSiteIncompleteOrContradictoryBrowserMetadata(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()

	for name, headers := range map[string]map[string]string{
		"exact origin with cross-site metadata": {
			"Origin": ts.URL, "Sec-Fetch-Site": "cross-site",
			"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
		},
		"foreign origin with same-origin metadata": {
			"Origin": "https://attacker.example", "Sec-Fetch-Site": "same-origin",
			"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
		},
		"opaque origin with cross-site metadata": {
			"Origin": "null", "Sec-Fetch-Site": "cross-site",
			"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
		},
		"incomplete metadata": {
			"Sec-Fetch-Site": "same-origin",
		},
	} {
		t.Run(name, func(t *testing.T) {
			resp := submitUILogin(t, ts.URL, mintUICode(t, ts.URL, "admin-secret"), headers)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden || len(resp.Cookies()) != 0 {
				t.Fatalf("rejected browser login status/cookies = %d/%d", resp.StatusCode, len(resp.Cookies()))
			}
		})
	}
}

func TestUILoginFailureRendersRetryableHTMLWithoutEchoingCode(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()

	const rejectedCode = "DO_NOT_ECHO_REJECTED_LOGIN_CODE"
	resp := submitUILogin(t, ts.URL, rejectedCode, map[string]string{"Origin": ts.URL})
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized ||
		!strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html;") ||
		!bytes.Contains(raw, []byte("Invalid or expired code")) ||
		!bytes.Contains(raw, []byte(`name="code"`)) ||
		bytes.Contains(raw, []byte(rejectedCode)) {
		t.Fatalf("unhelpful or unsafe login failure: status=%d type=%q body=%s",
			resp.StatusCode, resp.Header.Get("Content-Type"), raw)
	}
}

func TestUIDashboardRequiresSessionAndNeverPreloadsMessageContent(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.Send("amara", "athena", bus.SendOpts{
		Body:            "DASHBOARD_SECRET_BODY",
		Data:            json.RawMessage(`{"secret":"DASHBOARD_SECRET_DATA"}`),
		ClientMessageID: "dashboard-secret-client-id",
		AllowNew:        true,
	}); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()

	getDashboard := func(cookie *http.Cookie) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/", nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return resp, raw
	}

	resp, raw := getDashboard(nil)
	if resp.StatusCode != http.StatusOK || !bytes.Contains(raw, []byte(`name="code"`)) {
		t.Fatalf("unauthenticated UI did not return only the login shell: %d %s", resp.StatusCode, raw)
	}
	for _, forbidden := range []string{"amara", "athena", "DASHBOARD_SECRET"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("unauthenticated UI exposed %q: %s", forbidden, raw)
		}
	}

	bootstrap, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/bootstrap", bytes.NewBufferString(`{}`))
	bootstrap.Header.Set("Content-Type", "application/json")
	bootstrap.Header.Set("Authorization", "Bearer admin-secret")
	bootstrapResp, err := http.DefaultClient.Do(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	var minted struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(bootstrapResp.Body).Decode(&minted); err != nil {
		t.Fatal(err)
	}
	bootstrapResp.Body.Close()
	form := url.Values{"code": {minted.Code}}
	login, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/login", strings.NewReader(form.Encode()))
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	login.Header.Set("Origin", ts.URL)
	noRedirect := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	loginResp, err := noRedirect.Do(login)
	if err != nil {
		t.Fatal(err)
	}
	cookie := loginResp.Cookies()[0]
	loginResp.Body.Close()

	resp, raw = getDashboard(cookie)
	if resp.StatusCode != http.StatusOK || !bytes.Contains(raw, []byte("amara")) ||
		!bytes.Contains(raw, []byte("athena")) {
		t.Fatalf("authenticated dashboard missing routing metadata: %d %s", resp.StatusCode, raw)
	}
	for _, forbidden := range []string{"DASHBOARD_SECRET_BODY", "DASHBOARD_SECRET_DATA", "dashboard-secret-client-id"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("dashboard preloaded %q: %s", forbidden, raw)
		}
	}
	if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("Cache-Control") != "no-store" ||
		resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("dashboard hardening headers are incomplete: %v", resp.Header)
	}
}

func TestUIRevealIsExplicitSessionBoundAndEscapesHostileContent(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	replyTo := "msg_00000000000000000000000000000001"
	sent, err := b.Send("amara", "athena", bus.SendOpts{
		Body:            `<script>alert("body")</script></pre><img src=x onerror=alert(1)>`,
		Data:            json.RawMessage(`{"html":"<svg onload=alert(2)>"}`),
		ReplyTo:         &replyTo,
		ClientMessageID: "reveal-hostile-client-id",
		AllowNew:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()

	reveal := func(cookie *http.Cookie) (*http.Response, []byte) {
		t.Helper()
		form := url.Values{"message_id": {sent.MessageID}}
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/reveal", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", ts.URL)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return resp, raw
	}

	resp, raw := reveal(nil)
	if resp.StatusCode != http.StatusUnauthorized || bytes.Contains(raw, []byte("alert")) {
		t.Fatalf("unauthenticated reveal status/body = %d %s", resp.StatusCode, raw)
	}

	cookie := loginUI(t, ts.URL, "admin-secret")
	resp, raw = reveal(cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated reveal status = %d: %s", resp.StatusCode, raw)
	}
	for _, unsafe := range []string{"<script>", "</pre><img", "<svg onload"} {
		if bytes.Contains(raw, []byte(unsafe)) {
			t.Fatalf("reveal rendered hostile content as markup %q: %s", unsafe, raw)
		}
	}
	for _, escaped := range []string{"&lt;script&gt;", "&lt;/pre&gt;", `\u003csvg onload=alert(2)\u003e`} {
		if !bytes.Contains(raw, []byte(escaped)) {
			t.Fatalf("reveal omitted escaped content %q: %s", escaped, raw)
		}
	}
	if bytes.Contains(raw, []byte("reveal-hostile-client-id")) {
		t.Fatal("explicit content reveal exposed the caller idempotency key")
	}
}

func TestUILogoutInvalidatesTheServerSideSession(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()
	cookie := loginUI(t, ts.URL, "admin-secret")

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/logout", nil)
	req.Header.Set("Origin", ts.URL)
	req.AddCookie(cookie)
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || len(resp.Cookies()) != 1 || resp.Cookies()[0].MaxAge >= 0 {
		t.Fatalf("logout status/cookie = %d %+v", resp.StatusCode, resp.Cookies())
	}

	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/ui/", nil)
	req.AddCookie(cookie)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`name="code"`)) {
		t.Fatalf("logged-out session remained valid: %s", raw)
	}
}

func TestUIIsDisabledWhenAdministratorAuthenticationIsOff(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&Server{Bus: b}).Handler())
	defer ts.Close()

	for _, path := range []string{"/ui", "/ui/", "/ui/style.css"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("auth-off %s status = %d, want 404", path, resp.StatusCode)
		}
	}
	for _, path := range []string{"/ui/bootstrap", "/ui/login", "/ui/logout", "/ui/reveal"} {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("auth-off %s status = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestUIIsExplicitlyDisableableWithoutDisablingTheDaemon(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	agentToken, err := b.Mint("amara")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer((&Server{
		Bus: b, AdminToken: "admin-secret", DisableUI: true,
	}).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disabled UI affected daemon readiness: %d", resp.StatusCode)
	}
	for _, tc := range []struct {
		path  string
		token string
	}{
		{"/roster", agentToken},
		{"/activity", "admin-secret"},
	} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+tc.token)
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("disabled UI affected %s: %d", tc.path, resp.StatusCode)
		}
	}

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/ui"},
		{http.MethodGet, "/ui/"},
		{http.MethodGet, "/ui/style.css"},
		{http.MethodPost, "/ui/bootstrap"},
		{http.MethodPost, "/ui/login"},
		{http.MethodPost, "/ui/reveal"},
		{http.MethodPost, "/ui/logout"},
	} {
		req, _ := http.NewRequest(tc.method, ts.URL+tc.path, bytes.NewBufferString(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer admin-secret")
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("disabled %s %s status = %d, want 404", tc.method, tc.path, resp.StatusCode)
		}
	}
}

func TestUISessionCookieHasNoAdministratorAuthority(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()
	cookie := loginUI(t, ts.URL, "admin-secret")

	for _, path := range []string{"/activity", "/audit", "/backlog"} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		req.AddCookie(cookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("UI cookie authorized GET %s: status=%d", path, resp.StatusCode)
		}
	}
	for _, path := range []string{"/mint", "/skip", "/retire", "/prune"} {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewBufferString(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("UI cookie authorized POST %s: status=%d", path, resp.StatusCode)
		}
	}
}

func TestUIRejectsWrongHostAndCrossSitePosts(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	sent, err := b.Send("amara", "athena", bus.SendOpts{
		Body: "CROSS_SITE_SECRET", ClientMessageID: "cross-site", AllowNew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()
	cookie := loginUI(t, ts.URL, "admin-secret")

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/", nil)
	req.Host = "attacker.example"
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("wrong-host dashboard status = %d, want 404", resp.StatusCode)
	}

	for _, origin := range []string{"", "null", "https://attacker.example"} {
		form := url.Values{"message_id": {sent.MessageID}}
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/reveal", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		req.AddCookie(cookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusForbidden || bytes.Contains(raw, []byte("CROSS_SITE_SECRET")) {
			t.Fatalf("origin %q status/body = %d %s", origin, resp.StatusCode, raw)
		}
	}
}

func TestUISessionsExpireAndDoNotSurviveHandlerRestart(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.Send("amara", "athena", bus.SendOpts{
		Body: "SESSION_LIFETIME_SECRET", ClientMessageID: "session-lifetime", AllowNew: true,
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	newServer := func() *httptest.Server {
		return httptest.NewServer((&Server{
			Bus: b, AdminToken: "admin-secret", uiNow: func() time.Time { return now },
		}).Handler())
	}
	dashboard := func(serverURL string, cookie *http.Cookie) []byte {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, serverURL+"/ui/", nil)
		req.AddCookie(cookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	ts := newServer()
	cookie := loginUI(t, ts.URL, "admin-secret")
	if raw := dashboard(ts.URL, cookie); !bytes.Contains(raw, []byte("amara")) {
		t.Fatalf("fresh session was not accepted: %s", raw)
	}
	now = now.Add(uiSessionTTL + time.Second)
	if raw := dashboard(ts.URL, cookie); bytes.Contains(raw, []byte("amara")) ||
		!bytes.Contains(raw, []byte(`name="code"`)) {
		t.Fatalf("expired session remained active: %s", raw)
	}

	freshCookie := loginUI(t, ts.URL, "admin-secret")
	ts.Close()
	ts = newServer()
	defer ts.Close()
	if raw := dashboard(ts.URL, freshCookie); bytes.Contains(raw, []byte("amara")) ||
		!bytes.Contains(raw, []byte(`name="code"`)) {
		t.Fatalf("session crossed a handler restart: %s", raw)
	}
}

func TestUIAssertionCreatesBoundOperatorSessionAndSendsAttributedMessage(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "ui-test", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(
				big.NewInt(int64(key.E)).Bytes(),
			),
		}}})
	}))
	defer jwksServer.Close()

	const (
		issuer       = "https://edge.example"
		publicOrigin = "https://agentbus.example.com"
	)
	verifier := oidcauth.NewRemote(
		context.Background(),
		issuer,
		"agentbus-ui",
		jwksServer.URL,
		"oid",
		"AgentBus.Operator",
	)
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.BindExternalIdentity("alex.operator", "operator", issuer, "operator-oid"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Mint("worker"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer((&Server{
		Bus: b, AdminToken: "admin-secret",
		UIAssertionVerifier: verifier,
		UIAssertionHeader:   "X-Edge-Assertion",
		UIPublicOrigin:      publicOrigin,
		UILogoutURL:         publicOrigin + "/cdn-cgi/access/logout",
	}).Handler())
	defer ts.Close()

	token := signUIJWT(t, key, map[string]any{
		"iss": issuer,
		"aud": "agentbus-ui",
		"sub": "unstable-sub",
		"oid": "operator-oid",
		"exp": time.Now().Add(time.Hour).Unix(),
		"roles": []string{
			"AgentBus.Operator",
		},
	})
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/messages", nil)
	req.Host = "agentbus.example.com"
	req.Header.Set("X-Edge-Assertion", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !bytes.Contains(raw, []byte("Send as alex.operator")) {
		t.Fatalf("operator messages page = %d %s", resp.StatusCode, raw)
	}
	if len(resp.Cookies()) != 1 || !resp.Cookies()[0].Secure ||
		!resp.Cookies()[0].HttpOnly || resp.Cookies()[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("operator session cookie = %+v", resp.Cookies())
	}
	cookie := resp.Cookies()[0]
	commandMatch := regexp.MustCompile(
		`name="client_message_id" value="([^"]+)"`,
	).FindSubmatch(raw)
	if len(commandMatch) != 2 || !validUIClientMessageID(string(commandMatch[1])) {
		t.Fatalf("messages page omitted server-generated command identifier: %s", raw)
	}

	form := url.Values{
		"to":                {"worker"},
		"body":              {"status please"},
		"reply_to":          {""},
		"client_message_id": {string(commandMatch[1])},
	}
	noRedirect := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	for attempt := 0; attempt < 2; attempt++ {
		req, _ = http.NewRequest(http.MethodPost, ts.URL+"/ui/send", strings.NewReader(form.Encode()))
		req.Host = "agentbus.example.com"
		req.Header.Set("Origin", publicOrigin)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		resp, err = noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/ui/messages" {
			t.Fatalf(
				"operator send attempt %d = %d location=%q",
				attempt,
				resp.StatusCode,
				resp.Header.Get("Location"),
			)
		}
	}
	routes, err := b.RecentRoutes(0, 10)
	if err != nil || len(routes) != 1 {
		t.Fatalf("routes after operator send = %+v, %v", routes, err)
	}
	message, err := b.MessageContent(routes[0].MessageID)
	if err != nil || message.From != "alex.operator" || message.To != "worker" ||
		message.Body != "status please" {
		t.Fatalf("attributed operator message = %+v, %v", message, err)
	}

	events, err := b.AuditEvents(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var auditCount int
	for _, event := range events {
		if event.Action == "operator_send" {
			auditCount++
		}
	}
	if auditCount != 1 {
		t.Fatalf("idempotent retry produced %d operator_send events", auditCount)
	}

	replyTo := message.MessageID
	reply, err := b.Send("worker", "alex.operator", bus.SendOpts{
		Body:            `<script>alert("reply")</script>`,
		Data:            json.RawMessage(`{"html":"<svg onload=alert(2)>"}`),
		ReplyTo:         &replyTo,
		ClientMessageID: "agent-operator-reply",
	})
	if err != nil {
		t.Fatal(err)
	}
	conversation := func(messageID string) (int, []byte) {
		t.Helper()
		form := url.Values{"message_id": {messageID}}
		req, _ := http.NewRequest(
			http.MethodPost,
			ts.URL+"/ui/conversation",
			strings.NewReader(form.Encode()),
		)
		req.Host = "agentbus.example.com"
		req.Header.Set("Origin", publicOrigin)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, raw
	}
	status, raw := conversation(message.MessageID)
	if status != http.StatusOK {
		t.Fatalf("operator conversation = %d %s", status, raw)
	}
	for _, unsafe := range []string{"<script>", "<svg onload"} {
		if bytes.Contains(raw, []byte(unsafe)) {
			t.Fatalf("conversation rendered hostile content as markup %q: %s", unsafe, raw)
		}
	}
	for _, expected := range []string{
		"&lt;script&gt;",
		`\u003csvg onload=alert(2)\u003e`,
		`name="to" value="worker"`,
		`name="reply_to" value="` + reply.MessageID + `"`,
		`name="client_message_id" value="operator-ui-`,
	} {
		if !bytes.Contains(raw, []byte(expected)) {
			t.Fatalf("conversation omitted %q: %s", expected, raw)
		}
	}
	status, raw = conversation("msg_00000000000000000000000000000000")
	if status != http.StatusNotFound || bytes.Contains(raw, []byte("status please")) {
		t.Fatalf("missing conversation = %d %s", status, raw)
	}

	operator, err := b.AuthenticateExternal(
		issuer,
		"operator-oid",
		time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	parent := reply.MessageID
	for i := 0; i < 100; i++ {
		next, err := b.SendAsOperator(operator, "worker", bus.SendOpts{
			Body:            fmt.Sprintf("bounded-reply-%d", i),
			ReplyTo:         &parent,
			ClientMessageID: fmt.Sprintf("bounded-ui-conversation-%d", i),
		})
		if err != nil {
			t.Fatal(err)
		}
		parent = next.MessageID
	}
	status, raw = conversation(message.MessageID)
	if status != http.StatusOK ||
		!bytes.Contains(raw, []byte("This view is capped at 100 retained messages.")) {
		t.Fatalf("truncated conversation = %d %s", status, raw)
	}

	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/ui/logout", nil)
	req.Host = "agentbus.example.com"
	req.Header.Set("Origin", publicOrigin)
	req.AddCookie(cookie)
	resp, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther ||
		resp.Header.Get("Location") != publicOrigin+"/cdn-cgi/access/logout" ||
		len(resp.Cookies()) != 1 || resp.Cookies()[0].MaxAge >= 0 {
		t.Fatalf(
			"edge logout status/location/cookie = %d %q %+v",
			resp.StatusCode,
			resp.Header.Get("Location"),
			resp.Cookies(),
		)
	}
}

func TestNativeUISessionCannotSendOrImpersonate(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.Mint("worker"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()
	cookie := loginUI(t, ts.URL, "admin-secret")

	for name, form := range map[string]url.Values{
		"native session": {
			"to": {"worker"}, "body": {"forbidden"}, "reply_to": {""},
		},
		"impersonation field": {
			"from": {"victim"}, "to": {"worker"}, "body": {"forbidden"}, "reply_to": {""},
		},
	} {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest(
				http.MethodPost,
				ts.URL+"/ui/send",
				strings.NewReader(form.Encode()),
			)
			req.Header.Set("Origin", ts.URL)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(cookie)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("send status = %d", resp.StatusCode)
			}
		})
	}
	routes, err := b.RecentRoutes(0, 10)
	if err != nil || len(routes) != 0 {
		t.Fatalf("forbidden UI send created routes: %+v, %v", routes, err)
	}
}

func signUIJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": "ui-test", "typ": "JWT"})
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

func TestEveryUIOutcomeCarriesBrowserHardeningHeaders(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()

	requests := []*http.Request{}
	for _, path := range []string{"/ui/", "/ui/missing"} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		requests = append(requests, req)
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/reveal", nil)
	req.Header.Set("Origin", "null")
	requests = append(requests, req)
	for _, request := range requests {
		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.Header.Get("Cache-Control") != "no-store" ||
			resp.Header.Get("Content-Security-Policy") == "" ||
			resp.Header.Get("X-Frame-Options") != "DENY" ||
			resp.Header.Get("X-Content-Type-Options") != "nosniff" ||
			resp.Header.Get("Referrer-Policy") != "no-referrer" ||
			resp.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("%s %s status=%d missing hardening: %v", request.Method, request.URL.Path, resp.StatusCode, resp.Header)
		}
	}
}

func TestUIRevealReturnsNotFoundForMissingRetainedMessage(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()
	cookie := loginUI(t, ts.URL, "admin-secret")

	missing := "msg_00000000000000000000000000000000"
	form := url.Values{"message_id": {missing}}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/reveal", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound || bytes.Contains(raw, []byte(missing)) {
		t.Fatalf("missing reveal status/body = %d %s", resp.StatusCode, raw)
	}
}

func TestUIInspectionRemainsBodyFreeDuringConcurrentTraffic(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	retained, err := b.Send("amara", "athena", bus.SendOpts{
		Body: "CONCURRENT_REVEAL_BODY", ClientMessageID: "concurrent-retained", AllowNew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()
	cookie := loginUI(t, ts.URL, "admin-secret")

	var wg sync.WaitGroup
	errs := make(chan error, 24)
	for i := 0; i < 8; i++ {
		i := i
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, err := b.Send("amara", "athena", bus.SendOpts{
				Body:            fmt.Sprintf("CONCURRENT_SECRET_%d", i),
				ClientMessageID: fmt.Sprintf("concurrent-send-%d", i),
			})
			if err != nil {
				errs <- err
			}
		}()
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/", nil)
			req.AddCookie(cookie)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errs <- err
				return
			}
			raw, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				errs <- readErr
			} else if resp.StatusCode != http.StatusOK || bytes.Contains(raw, []byte("CONCURRENT_SECRET_")) {
				errs <- fmt.Errorf("dashboard status/body = %d %s", resp.StatusCode, raw)
			}
		}()
		go func() {
			defer wg.Done()
			form := url.Values{"message_id": {retained.MessageID}}
			req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/reveal", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", ts.URL)
			req.AddCookie(cookie)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errs <- err
				return
			}
			_, readErr := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if readErr != nil {
				errs <- readErr
			} else if resp.StatusCode != http.StatusOK {
				errs <- fmt.Errorf("reveal status = %d", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestHTTPAuditValidatesAndForwardsBoundedPagination(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, name := range []string{"amara", "athena", "solane"} {
		if _, err := b.Mint(name); err != nil {
			t.Fatal(err)
		}
	}
	ts := httptest.NewServer((&Server{Bus: b, AdminToken: "admin-secret"}).Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/audit?after_id=1&limit=1", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var events []bus.AuditEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || len(events) != 1 || events[0].ID <= 1 {
		t.Fatalf("status=%d events=%+v", resp.StatusCode, events)
	}

	for _, query := range []string{
		"?after_id=-1", "?after_id=nope", "?limit=0", "?limit=1001",
		"?wat=1", "?limit=1&limit=2",
	} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/audit"+query, nil)
		req.Header.Set("Authorization", "Bearer admin-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("query %q status = %d", query, resp.StatusCode)
		}
	}
}

func TestGuardListen(t *testing.T) {
	if err := GuardListen("127.0.0.1:7777", false); err != nil {
		t.Errorf("loopback without auth must be allowed: %v", err)
	}
	if err := GuardListen("localhost:7777", false); err != nil {
		t.Errorf("localhost without auth must be allowed: %v", err)
	}
	if err := GuardListen("0.0.0.0:7777", false); err == nil {
		t.Error("non-loopback without auth must be refused")
	}
	if err := GuardListen("0.0.0.0:7777", true); err == nil {
		t.Error("non-loopback plaintext must be refused even with bearer authentication")
	}
	if !loopbackHost("agentbus.localhost:17777") {
		t.Error("the dedicated operator UI hostname must be accepted")
	}
	if loopbackHost("evil.localhost:17777") {
		t.Error("the operator UI hostname allowlist must remain exact")
	}
}
