package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jahwag/agentbus/internal/bus"
)

type tokenOIDCProvider struct {
	*httptest.Server
	key                *rsa.PrivateKey
	expectedNonce      string
	pkceChallenge      string
	tokenNonceOverride string
	tokenSubject       string
	tokenOIDOverride   any
	tokenRoles         any
	tokenAudience      any
	tokenAZP           any
	tokenIssuer        string
	tokenExpiresAt     time.Time
	tokenSigningKey    *rsa.PrivateKey
	omitOID            bool
	omitIDToken        bool
	tokenStatus        int
}

func newTokenOIDCProvider(t *testing.T) *tokenOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &tokenOIDCProvider{
		key:           key,
		tokenSubject:  "operator-oid",
		tokenRoles:    []string{"AgentBus.Operator"},
		tokenAudience: "agentbus-browser",
	}
	fixture.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                fixture.URL,
				"authorization_endpoint":                fixture.URL + "/authorize",
				"token_endpoint":                        fixture.URL + "/token",
				"jwks_uri":                              fixture.URL + "/keys",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA",
				"kid": "ui-test",
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(
					big.NewInt(int64(key.E)).Bytes(),
				),
			}}})
		case "/token":
			if fixture.tokenStatus != 0 {
				http.Error(w, "token exchange failed", fixture.tokenStatus)
				return
			}
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse token request: %v", err)
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			clientID, clientSecret, _ := r.BasicAuth()
			if clientID != "agentbus-browser" || clientSecret != "test-secret" {
				t.Errorf("token client credentials = %q/%q", clientID, clientSecret)
			}
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "test-code" ||
				r.Form.Get("redirect_uri") != "https://agentbus.example.com/ui/auth/oidc/callback" {
				t.Errorf("token request form = %v", r.Form)
			}
			verifierDigest := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if got := base64.RawURLEncoding.EncodeToString(verifierDigest[:]); got != fixture.pkceChallenge {
				t.Errorf("PKCE challenge = %q, want %q", got, fixture.pkceChallenge)
			}
			nonce := fixture.expectedNonce
			if fixture.tokenNonceOverride != "" {
				nonce = fixture.tokenNonceOverride
			}
			oidClaim := any(fixture.tokenSubject)
			if fixture.tokenOIDOverride != nil {
				oidClaim = fixture.tokenOIDOverride
			}
			now := time.Now()
			issuer := fixture.URL
			if fixture.tokenIssuer != "" {
				issuer = fixture.tokenIssuer
			}
			expiresAt := now.Add(time.Hour)
			if !fixture.tokenExpiresAt.IsZero() {
				expiresAt = fixture.tokenExpiresAt
			}
			claims := map[string]any{
				"iss":   issuer,
				"aud":   fixture.tokenAudience,
				"sub":   "unstable-subject",
				"nonce": nonce,
				"iat":   now.Add(-time.Minute).Unix(),
				"exp":   expiresAt.Unix(),
				"roles": fixture.tokenRoles,
			}
			if !fixture.omitOID {
				claims["oid"] = oidClaim
			}
			if fixture.tokenAZP != nil {
				claims["azp"] = fixture.tokenAZP
			}
			signingKey := key
			if fixture.tokenSigningKey != nil {
				signingKey = fixture.tokenSigningKey
			}
			idToken := signUIJWT(t, signingKey, claims)
			response := map[string]any{
				"access_token": "unused-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			}
			if !fixture.omitIDToken {
				response["id_token"] = idToken
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fixture.Close)
	return fixture
}

func startBoundOIDCFlow(t *testing.T) (*tokenOIDCProvider, *BrowserOIDC, *bus.Bus, *httptest.Server, *http.Client, *http.Cookie) {
	t.Helper()
	provider := newTokenOIDCProvider(t)
	oidcLogin, err := NewBrowserOIDC(context.Background(), BrowserOIDCConfig{
		Issuer:       provider.URL,
		ClientID:     "agentbus-browser",
		ClientSecret: "test-secret",
		RedirectURL:  "https://agentbus.example.com/ui/auth/oidc/callback",
		SubjectClaim: "oid",
		RequiredRole: "AgentBus.Operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := b.BindExternalIdentity("alex.operator", "operator", provider.URL, "operator-oid"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer((&Server{
		Bus:            b,
		AdminToken:     "admin-secret",
		UIOIDC:         oidcLogin,
		UIPublicOrigin: "https://agentbus.example.com",
	}).Handler())
	t.Cleanup(ts.Close)
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	flowCookie := startOIDCOnServer(t, provider, ts, client)
	return provider, oidcLogin, b, ts, client, flowCookie
}

func startOIDCOnServer(t *testing.T, provider *tokenOIDCProvider, ts *httptest.Server, client *http.Client) *http.Cookie {
	return startOIDCOnServerWithSession(t, provider, ts, client, nil)
}

func startOIDCOnServerWithSession(t *testing.T, provider *tokenOIDCProvider, ts *httptest.Server, client *http.Client, sessionCookie *http.Cookie) *http.Cookie {
	t.Helper()
	start, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/auth/oidc/start", nil)
	start.Host = "agentbus.example.com"
	start.Header.Set("Sec-Fetch-Site", "same-origin")
	start.Header.Set("Sec-Fetch-Mode", "navigate")
	start.Header.Set("Sec-Fetch-Dest", "document")
	if sessionCookie != nil {
		start.AddCookie(sessionCookie)
	}
	response, err := client.Do(start)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	authorizationURL, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	provider.expectedNonce = authorizationURL.Query().Get("nonce")
	provider.pkceChallenge = authorizationURL.Query().Get("code_challenge")
	return response.Cookies()[0]
}

func finishOIDCFlow(t *testing.T, ts *httptest.Server, client *http.Client, flowCookie *http.Cookie) *http.Response {
	t.Helper()
	callbackURL := ts.URL + "/ui/auth/oidc/callback?state=" + url.QueryEscape(flowCookie.Value) + "&code=test-code"
	callback, _ := http.NewRequest(http.MethodGet, callbackURL, nil)
	callback.Host = "agentbus.example.com"
	callback.AddCookie(flowCookie)
	response, err := client.Do(callback)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func isUISessionCookie(cookie *http.Cookie) bool {
	return strings.HasSuffix(cookie.Name, "agentbus_ui_session")
}

func testOIDCProvider(t *testing.T) *httptest.Server {
	t.Helper()
	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                provider.URL,
				"authorization_endpoint":                provider.URL + "/authorize",
				"token_endpoint":                        provider.URL + "/token",
				"jwks_uri":                              provider.URL + "/keys",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			}); err != nil {
				t.Errorf("write discovery: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)
	return provider
}

func TestBrowserOIDCPreservesExactIssuerIdentifier(t *testing.T) {
	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                provider.URL + "/",
			"authorization_endpoint":                provider.URL + "/authorize",
			"token_endpoint":                        provider.URL + "/token",
			"jwks_uri":                              provider.URL + "/keys",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer provider.Close()

	if _, err := NewBrowserOIDC(context.Background(), BrowserOIDCConfig{
		Issuer:      provider.URL + "/",
		ClientID:    "agentbus-browser",
		RedirectURL: "https://agentbus.example.com/ui/auth/oidc/callback",
	}); err != nil {
		t.Fatalf("trailing-slash issuer rejected: %v", err)
	}
}

func TestBrowserOIDCRejectsPlaintextNonLoopbackRedirect(t *testing.T) {
	provider := testOIDCProvider(t)
	_, err := NewBrowserOIDC(context.Background(), BrowserOIDCConfig{
		Issuer:      provider.URL,
		ClientID:    "agentbus-browser",
		RedirectURL: "http://agentbus.example.com/ui/auth/oidc/callback",
	})
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("plaintext public redirect error = %v, want HTTPS rejection", err)
	}
}

func TestUIOIDCDiscoveryOutageDoesNotPreventStartupAndCanRecover(t *testing.T) {
	var unavailable atomic.Bool
	unavailable.Store(true)
	var discoveryRequests atomic.Int32
	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		discoveryRequests.Add(1)
		if unavailable.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
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
	oidcLogin, err := NewBrowserOIDC(context.Background(), BrowserOIDCConfig{
		Issuer:      provider.URL,
		ClientID:    "agentbus-browser",
		RedirectURL: "https://agentbus.example.com/ui/auth/oidc/callback",
	})
	if err != nil {
		t.Fatalf("OIDC configuration should not require live discovery: %v", err)
	}
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	oidcLogin.now = func() time.Time { return now }
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&Server{
		Bus:            b,
		AdminToken:     "admin-secret",
		UIOIDC:         oidcLogin,
		UIPublicOrigin: "https://agentbus.example.com",
	}).Handler())
	defer ts.Close()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	start := func() int {
		request, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/auth/oidc/start", nil)
		request.Host = "agentbus.example.com"
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		request.Header.Set("Sec-Fetch-Mode", "navigate")
		request.Header.Set("Sec-Fetch-Dest", "document")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	if got := start(); got != http.StatusServiceUnavailable {
		t.Fatalf("outage start status = %d, want 503", got)
	}
	if got := start(); got != http.StatusServiceUnavailable || discoveryRequests.Load() != 1 {
		t.Fatalf("cooldown start status/requests = %d/%d, want 503/1", got, discoveryRequests.Load())
	}
	unavailable.Store(false)
	now = now.Add(uiOIDCDiscoveryRetry + time.Second)
	if got := start(); got != http.StatusFound || discoveryRequests.Load() != 2 {
		t.Fatalf("recovered start status/requests = %d/%d, want 302/2", got, discoveryRequests.Load())
	}
}

func TestBrowserOIDCDiscoveryIsIndependentOfCallerCancellation(t *testing.T) {
	provider := testOIDCProvider(t)
	oidcLogin, err := NewBrowserOIDC(context.Background(), BrowserOIDCConfig{
		Issuer:      provider.URL,
		ClientID:    "agentbus-browser",
		RedirectURL: "https://agentbus.example.com/ui/auth/oidc/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := oidcLogin.ensureProvider(canceled); err != nil {
		t.Fatalf("caller cancellation poisoned shared discovery: %v", err)
	}
}

func TestUIConfiguredOIDCLoginIsExposed(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ts := httptest.NewServer((&Server{
		Bus:            b,
		AdminToken:     "admin-secret",
		UIOIDC:         &BrowserOIDC{},
		UIPublicOrigin: "https://agentbus.example.com",
	}).Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/ui/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "agentbus.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}
	if !bytes.Contains(body, []byte(`href="/ui/auth/oidc/start"`)) {
		t.Fatalf("OIDC login entry point missing: %s", body)
	}
}

func TestUIOIDCOnlyLoginDoesNotOfferUnavailableAdminCode(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&Server{
		Bus:            b,
		UIOIDC:         &BrowserOIDC{},
		UIPublicOrigin: "https://agentbus.example.com",
	}).Handler())
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/", nil)
	req.Host = "agentbus.example.com"
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`href="/ui/auth/oidc/start"`)) || bytes.Contains(body, []byte(`name="code"`)) {
		t.Fatalf("OIDC-only login offered wrong entry modes: %s", body)
	}
}

func TestUIOIDCStartUsesStateNoncePKCEAndSecureFlowCookie(t *testing.T) {
	provider := testOIDCProvider(t)
	oidcLogin, err := NewBrowserOIDC(context.Background(), BrowserOIDCConfig{
		Issuer:       provider.URL,
		ClientID:     "agentbus-browser",
		ClientSecret: "test-secret",
		RedirectURL:  "https://agentbus.example.com/ui/auth/oidc/callback",
		SubjectClaim: "oid",
		RequiredRole: "AgentBus.Operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&Server{
		Bus:            b,
		AdminToken:     "admin-secret",
		UIOIDC:         oidcLogin,
		UIPublicOrigin: "https://agentbus.example.com",
	}).Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/ui/auth/oidc/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "agentbus.example.com"
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start status = %d, want 302", resp.StatusCode)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := location.Query()
	for key, want := range map[string]string{
		"response_type":         "code",
		"client_id":             "agentbus-browser",
		"redirect_uri":          "https://agentbus.example.com/ui/auth/oidc/callback",
		"scope":                 "openid profile email",
		"code_challenge_method": "S256",
	} {
		if got := query.Get(key); got != want {
			t.Errorf("authorization %s = %q, want %q", key, got, want)
		}
	}
	for _, key := range []string{"state", "nonce", "code_challenge"} {
		if query.Get(key) == "" {
			t.Errorf("authorization %s is empty", key)
		}
	}
	if got := resp.Cookies(); len(got) != 1 || !strings.HasPrefix(got[0].Name, "__Host-") ||
		got[0].Value != query.Get("state") || got[0].Path != "/" ||
		!got[0].Secure || !got[0].HttpOnly || got[0].SameSite != http.SameSiteLaxMode ||
		got[0].MaxAge != int(uiOIDCFlowTTL.Seconds()) {
		t.Fatalf("OIDC flow cookie = %+v", got)
	}
}

func TestUIOIDCCallbackCreatesBoundOperatorSession(t *testing.T) {
	provider := newTokenOIDCProvider(t)
	oidcLogin, err := NewBrowserOIDC(context.Background(), BrowserOIDCConfig{
		Issuer:       provider.URL,
		ClientID:     "agentbus-browser",
		ClientSecret: "test-secret",
		RedirectURL:  "https://agentbus.example.com/ui/auth/oidc/callback",
		SubjectClaim: "oid",
		RequiredRole: "AgentBus.Operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.BindExternalIdentity("alex.operator", "operator", provider.URL, "operator-oid"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer((&Server{
		Bus:            b,
		AdminToken:     "admin-secret",
		UIOIDC:         oidcLogin,
		UIPublicOrigin: "https://agentbus.example.com",
	}).Handler())
	defer ts.Close()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	start, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/auth/oidc/start", nil)
	start.Host = "agentbus.example.com"
	start.Header.Set("Sec-Fetch-Site", "same-origin")
	start.Header.Set("Sec-Fetch-Mode", "navigate")
	start.Header.Set("Sec-Fetch-Dest", "document")
	startResponse, err := client.Do(start)
	if err != nil {
		t.Fatal(err)
	}
	startResponse.Body.Close()
	authorizationURL, err := url.Parse(startResponse.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	provider.expectedNonce = authorizationURL.Query().Get("nonce")
	provider.pkceChallenge = authorizationURL.Query().Get("code_challenge")
	flowCookie := startResponse.Cookies()[0]

	callbackURL := ts.URL + "/ui/auth/oidc/callback?state=" + url.QueryEscape(flowCookie.Value) + "&code=test-code"
	callback, _ := http.NewRequest(http.MethodGet, callbackURL, nil)
	callback.Host = "agentbus.example.com"
	callback.AddCookie(flowCookie)
	callbackResponse, err := client.Do(callback)
	if err != nil {
		t.Fatal(err)
	}
	defer callbackResponse.Body.Close()
	if callbackResponse.StatusCode != http.StatusSeeOther || callbackResponse.Header.Get("Location") != "/ui/" {
		body, _ := io.ReadAll(callbackResponse.Body)
		t.Fatalf("callback status/location = %d %q: %s", callbackResponse.StatusCode, callbackResponse.Header.Get("Location"), body)
	}
	var sessionCookie *http.Cookie
	for _, cookie := range callbackResponse.Cookies() {
		if isUISessionCookie(cookie) {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil ||
		!strings.HasPrefix(sessionCookie.Name, "__Host-") ||
		sessionCookie.Path != "/" ||
		!sessionCookie.Secure ||
		!sessionCookie.HttpOnly ||
		sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("operator session cookie = %+v", sessionCookie)
	}

	dashboard, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/messages", nil)
	dashboard.Host = "agentbus.example.com"
	dashboard.AddCookie(sessionCookie)
	dashboardResponse, err := client.Do(dashboard)
	if err != nil {
		t.Fatal(err)
	}
	defer dashboardResponse.Body.Close()
	body, err := io.ReadAll(dashboardResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	if dashboardResponse.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("Send as alex.operator")) {
		t.Fatalf("authenticated dashboard = %d %s", dashboardResponse.StatusCode, body)
	}
}

func TestUIOIDCIgnoresUnselectedProviderSpecificClaims(t *testing.T) {
	provider := newTokenOIDCProvider(t)
	provider.tokenOIDOverride = map[string]any{"provider": "specific"}
	provider.tokenRoles = "provider-specific-scalar"
	oidcLogin, err := NewBrowserOIDC(context.Background(), BrowserOIDCConfig{
		Issuer:       provider.URL,
		ClientID:     "agentbus-browser",
		ClientSecret: "test-secret",
		RedirectURL:  "https://agentbus.example.com/ui/auth/oidc/callback",
		SubjectClaim: "sub",
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.BindExternalIdentity("alex.operator", "operator", provider.URL, "unstable-subject"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer((&Server{
		Bus:            b,
		AdminToken:     "admin-secret",
		UIOIDC:         oidcLogin,
		UIPublicOrigin: "https://agentbus.example.com",
	}).Handler())
	defer ts.Close()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	start, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/auth/oidc/start", nil)
	start.Host = "agentbus.example.com"
	start.Header.Set("Sec-Fetch-Site", "same-origin")
	start.Header.Set("Sec-Fetch-Mode", "navigate")
	start.Header.Set("Sec-Fetch-Dest", "document")
	startResponse, err := client.Do(start)
	if err != nil {
		t.Fatal(err)
	}
	startResponse.Body.Close()
	authorizationURL, err := url.Parse(startResponse.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	provider.expectedNonce = authorizationURL.Query().Get("nonce")
	provider.pkceChallenge = authorizationURL.Query().Get("code_challenge")
	response := finishOIDCFlow(t, ts, client, startResponse.Cookies()[0])
	defer response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("sub callback with unrelated claims = %d, want 303: %s", response.StatusCode, body)
	}
}

func TestUIOIDCCallbackStateCannotBeReplayed(t *testing.T) {
	provider := newTokenOIDCProvider(t)
	oidcLogin, err := NewBrowserOIDC(context.Background(), BrowserOIDCConfig{
		Issuer:       provider.URL,
		ClientID:     "agentbus-browser",
		ClientSecret: "test-secret",
		RedirectURL:  "https://agentbus.example.com/ui/auth/oidc/callback",
		SubjectClaim: "oid",
		RequiredRole: "AgentBus.Operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.BindExternalIdentity("alex.operator", "operator", provider.URL, "operator-oid"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer((&Server{
		Bus:            b,
		AdminToken:     "admin-secret",
		UIOIDC:         oidcLogin,
		UIPublicOrigin: "https://agentbus.example.com",
	}).Handler())
	defer ts.Close()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	start, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/auth/oidc/start", nil)
	start.Host = "agentbus.example.com"
	start.Header.Set("Sec-Fetch-Site", "same-origin")
	start.Header.Set("Sec-Fetch-Mode", "navigate")
	start.Header.Set("Sec-Fetch-Dest", "document")
	startResponse, err := client.Do(start)
	if err != nil {
		t.Fatal(err)
	}
	startResponse.Body.Close()
	authorizationURL, err := url.Parse(startResponse.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	provider.expectedNonce = authorizationURL.Query().Get("nonce")
	provider.pkceChallenge = authorizationURL.Query().Get("code_challenge")
	flowCookie := startResponse.Cookies()[0]
	callbackURL := ts.URL + "/ui/auth/oidc/callback?state=" + url.QueryEscape(flowCookie.Value) + "&code=test-code"

	invokeCallback := func() *http.Response {
		t.Helper()
		callback, _ := http.NewRequest(http.MethodGet, callbackURL, nil)
		callback.Host = "agentbus.example.com"
		callback.AddCookie(flowCookie)
		response, err := client.Do(callback)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	first := invokeCallback()
	first.Body.Close()
	if first.StatusCode != http.StatusSeeOther {
		t.Fatalf("first callback status = %d, want 303", first.StatusCode)
	}
	second := invokeCallback()
	defer second.Body.Close()
	if second.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(second.Body)
		t.Fatalf("replayed callback status = %d, want 401: %s", second.StatusCode, body)
	}
}

func TestUIOIDCRejectsMultiAudienceTokenWithoutAuthorizedParty(t *testing.T) {
	provider, _, _, ts, client, flowCookie := startBoundOIDCFlow(t)
	provider.tokenAudience = []string{"agentbus-browser", "another-client"}
	response := finishOIDCFlow(t, ts, client, flowCookie)
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("multi-audience token without azp = %d, want 401: %s", response.StatusCode, body)
	}
}

func TestUIOIDCProviderErrorConsumesState(t *testing.T) {
	_, _, _, ts, client, flowCookie := startBoundOIDCFlow(t)
	state := url.QueryEscape(flowCookie.Value)

	refused, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/auth/oidc/callback?state="+state+"&error=access_denied", nil)
	refused.Host = "agentbus.example.com"
	refused.AddCookie(flowCookie)
	refusedResponse, err := client.Do(refused)
	if err != nil {
		t.Fatal(err)
	}
	refusedResponse.Body.Close()
	if refusedResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("provider error callback status = %d, want 401", refusedResponse.StatusCode)
	}

	replayed, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/auth/oidc/callback?state="+state+"&code=test-code", nil)
	replayed.Host = "agentbus.example.com"
	replayed.AddCookie(flowCookie)
	replayedResponse, err := client.Do(replayed)
	if err != nil {
		t.Fatal(err)
	}
	defer replayedResponse.Body.Close()
	if replayedResponse.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(replayedResponse.Body)
		t.Fatalf("callback after provider error status = %d, want 401: %s", replayedResponse.StatusCode, body)
	}
}

func TestUIOIDCCallbackRejectsUnauthorizedIdentity(t *testing.T) {
	tests := map[string]func(*testing.T, *tokenOIDCProvider, *bus.Bus){
		"wrong required role": func(_ *testing.T, provider *tokenOIDCProvider, _ *bus.Bus) {
			provider.tokenRoles = []string{"Other.Role"}
		},
		"wrong nonce": func(_ *testing.T, provider *tokenOIDCProvider, _ *bus.Bus) {
			provider.tokenNonceOverride = "nonce-from-another-flow"
		},
		"unbound identity": func(t *testing.T, provider *tokenOIDCProvider, b *bus.Bus) {
			if err := b.UnbindExternalIdentity(provider.URL, provider.tokenSubject); err != nil {
				t.Fatal(err)
			}
		},
		"agent identity": func(t *testing.T, provider *tokenOIDCProvider, b *bus.Bus) {
			if err := b.UnbindExternalIdentity(provider.URL, provider.tokenSubject); err != nil {
				t.Fatal(err)
			}
			if err := b.BindExternalIdentity("worker", "agent", provider.URL, provider.tokenSubject); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, configure := range tests {
		t.Run(name, func(t *testing.T) {
			provider, _, b, ts, client, flowCookie := startBoundOIDCFlow(t)
			configure(t, provider, b)
			response := finishOIDCFlow(t, ts, client, flowCookie)
			defer response.Body.Close()
			if response.StatusCode != http.StatusUnauthorized {
				body, _ := io.ReadAll(response.Body)
				t.Fatalf("unauthorized identity callback status = %d, want 401: %s", response.StatusCode, body)
			}
			for _, cookie := range response.Cookies() {
				if isUISessionCookie(cookie) && cookie.MaxAge >= 0 {
					t.Fatalf("unauthorized identity received session cookie: %+v", cookie)
				}
			}
		})
	}
}

func TestUIOIDCSessionIsInvalidatedWhenIdentityIsUnbound(t *testing.T) {
	provider, _, b, ts, client, flowCookie := startBoundOIDCFlow(t)
	callbackResponse := finishOIDCFlow(t, ts, client, flowCookie)
	callbackResponse.Body.Close()
	if callbackResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want 303", callbackResponse.StatusCode)
	}
	var sessionCookie *http.Cookie
	for _, cookie := range callbackResponse.Cookies() {
		if isUISessionCookie(cookie) {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil {
		t.Fatal("callback omitted operator session cookie")
	}
	if err := b.UnbindExternalIdentity(provider.URL, provider.tokenSubject); err != nil {
		t.Fatal(err)
	}

	dashboard, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/messages", nil)
	dashboard.Host = "agentbus.example.com"
	dashboard.AddCookie(sessionCookie)
	dashboardResponse, err := client.Do(dashboard)
	if err != nil {
		t.Fatal(err)
	}
	defer dashboardResponse.Body.Close()
	body, err := io.ReadAll(dashboardResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("Send as alex.operator")) || !bytes.Contains(body, []byte(`href="/ui/auth/oidc/start"`)) {
		t.Fatalf("unbound session retained operator access: %s", body)
	}
	var sessionCleared bool
	for _, cookie := range dashboardResponse.Cookies() {
		if isUISessionCookie(cookie) && cookie.MaxAge < 0 {
			sessionCleared = true
		}
	}
	if !sessionCleared {
		t.Fatal("unbound session cookie was not cleared")
	}
}

func TestPrincipalSessionQuotaAppliesWhenReplacingAnotherSessionKind(t *testing.T) {
	store := (&Server{}).newUICredentialStore()
	foreignDigest := sha256.Sum256([]byte("local-code-session"))
	store.sessions[foreignDigest] = uiSession{
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	principal := bus.AuthenticatedPrincipal{
		Name:      "alex.operator",
		Kind:      "operator",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	for i := 0; i < maxUISessionsPerPrincipal; i++ {
		if _, _, err := store.mintPrincipalSession(principal, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := store.mintPrincipalSessionReplacing(principal, foreignDigest, true); err != nil {
		t.Fatal(err)
	}
	principalSessions := 0
	for _, session := range store.sessions {
		if session.Principal != nil && session.Principal.Name == principal.Name {
			principalSessions++
		}
	}
	if principalSessions != maxUISessionsPerPrincipal {
		t.Fatalf("principal sessions = %d, want %d", principalSessions, maxUISessionsPerPrincipal)
	}
	if _, exists := store.sessions[foreignDigest]; exists {
		t.Fatal("replaced local-code session remained active")
	}
}

func TestUIOIDCRepeatedLoginCannotExhaustGlobalSessionCapacity(t *testing.T) {
	provider, _, _, ts, client, flowCookie := startBoundOIDCFlow(t)
	for login := 0; login <= maxUISessions; login++ {
		if login > 0 {
			flowCookie = startOIDCOnServer(t, provider, ts, client)
		}
		response := finishOIDCFlow(t, ts, client, flowCookie)
		response.Body.Close()
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("login %d status = %d, want 303", login+1, response.StatusCode)
		}
	}
}

func TestUIOIDCReauthenticationRevokesSessionPresentAtStart(t *testing.T) {
	provider, _, _, ts, client, flowCookie := startBoundOIDCFlow(t)
	first := finishOIDCFlow(t, ts, client, flowCookie)
	first.Body.Close()
	var oldSession *http.Cookie
	for _, cookie := range first.Cookies() {
		if isUISessionCookie(cookie) {
			oldSession = cookie
		}
	}
	if oldSession == nil {
		t.Fatal("first login omitted session cookie")
	}
	secondFlow := startOIDCOnServerWithSession(t, provider, ts, client, oldSession)
	second := finishOIDCFlow(t, ts, client, secondFlow)
	second.Body.Close()
	if second.StatusCode != http.StatusSeeOther {
		t.Fatalf("second login status = %d, want 303", second.StatusCode)
	}

	dashboard, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/messages", nil)
	dashboard.Host = "agentbus.example.com"
	dashboard.AddCookie(oldSession)
	response, err := client.Do(dashboard)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("Send as alex.operator")) {
		t.Fatalf("session present at reauthentication start remained valid: %s", body)
	}
}

func TestUIOIDCExpiredFlowIsRejected(t *testing.T) {
	_, oidcLogin, _, ts, client, flowCookie := startBoundOIDCFlow(t)
	oidcLogin.now = func() time.Time {
		return time.Now().Add(uiOIDCFlowTTL + time.Minute)
	}
	response := finishOIDCFlow(t, ts, client, flowCookie)
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("expired callback status = %d, want 401: %s", response.StatusCode, body)
	}
}

func TestUIOIDCAnonymousStartsDoNotConsumeServerAdmissionCapacity(t *testing.T) {
	_, _, _, ts, client, oldestCookie := startBoundOIDCFlow(t)
	for i := 0; i < 256; i++ {
		start, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/auth/oidc/start", nil)
		start.Host = "agentbus.example.com"
		start.Header.Set("Sec-Fetch-Site", "same-origin")
		start.Header.Set("Sec-Fetch-Mode", "navigate")
		start.Header.Set("Sec-Fetch-Dest", "document")
		response, err := client.Do(start)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusFound {
			t.Fatalf("start %d status = %d", i, response.StatusCode)
		}
	}
	response := finishOIDCFlow(t, ts, client, oldestCookie)
	defer response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("original callback status = %d, want 303: %s", response.StatusCode, body)
	}
}

func TestUIOIDCRejectsTamperedEncryptedFlowState(t *testing.T) {
	_, _, _, ts, client, flowCookie := startBoundOIDCFlow(t)
	state := []byte(flowCookie.Value)
	state[len(state)-1] ^= 1
	flowCookie.Value = string(state)
	response := finishOIDCFlow(t, ts, client, flowCookie)
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered flow callback status = %d, want 401", response.StatusCode)
	}
}

func TestOIDCOnlyPublicProxyPreservesRESTLocalMode(t *testing.T) {
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	origin := httptest.NewServer((&Server{
		Bus:            b,
		UIOIDC:         &BrowserOIDC{},
		UIPublicOrigin: "https://agentbus.example.com",
	}).Handler())
	defer origin.Close()
	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	edge := httptest.NewServer(httputil.NewSingleHostReverseProxy(target))
	defer edge.Close()

	request, _ := http.NewRequest(
		http.MethodPost,
		edge.URL+"/send",
		strings.NewReader(`{"from":"attacker","to":"victim","body":"forged"}`),
	)
	request.Host = "agentbus.example.com"
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("proxied auth-off REST status = %d, want 403: %s", response.StatusCode, body)
	}
}

func TestUIOIDCWorksWithoutAdminTokenWhileRESTRemainsLoopbackOnly(t *testing.T) {
	provider := testOIDCProvider(t)
	oidcLogin, err := NewBrowserOIDC(context.Background(), BrowserOIDCConfig{
		Issuer:      provider.URL,
		ClientID:    "agentbus-browser",
		RedirectURL: "https://agentbus.example.com/ui/auth/oidc/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&Server{
		Bus:            b,
		UIOIDC:         oidcLogin,
		UIPublicOrigin: "https://agentbus.example.com",
	}).Handler())
	defer ts.Close()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	start, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/auth/oidc/start", nil)
	start.Host = "agentbus.example.com"
	start.Header.Set("Sec-Fetch-Site", "same-origin")
	start.Header.Set("Sec-Fetch-Mode", "navigate")
	start.Header.Set("Sec-Fetch-Dest", "document")
	startResponse, err := client.Do(start)
	if err != nil {
		t.Fatal(err)
	}
	startResponse.Body.Close()
	if startResponse.StatusCode != http.StatusFound {
		t.Fatalf("OIDC-only UI start status = %d, want 302", startResponse.StatusCode)
	}

	roster, _ := http.NewRequest(http.MethodGet, ts.URL+"/roster", nil)
	roster.Host = "agentbus.example.com"
	rosterResponse, err := client.Do(roster)
	if err != nil {
		t.Fatal(err)
	}
	defer rosterResponse.Body.Close()
	if rosterResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("OIDC-only public REST status = %d, want 403", rosterResponse.StatusCode)
	}
}

func TestUIOIDCCallbackRejectsInvalidProviderTokens(t *testing.T) {
	tests := map[string]func(*testing.T, *tokenOIDCProvider){
		"wrong issuer": func(_ *testing.T, provider *tokenOIDCProvider) {
			provider.tokenIssuer = provider.URL + "/different-issuer"
		},
		"wrong audience": func(_ *testing.T, provider *tokenOIDCProvider) {
			provider.tokenAudience = "different-client"
		},
		"wrong signature": func(t *testing.T, provider *tokenOIDCProvider) {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			provider.tokenSigningKey = key
		},
		"expired token": func(_ *testing.T, provider *tokenOIDCProvider) {
			provider.tokenExpiresAt = time.Now().Add(-2 * time.Minute)
		},
		"wrong authorized party": func(_ *testing.T, provider *tokenOIDCProvider) {
			provider.tokenAudience = []string{"agentbus-browser", "another-client"}
			provider.tokenAZP = "another-client"
		},
		"missing selected oid": func(_ *testing.T, provider *tokenOIDCProvider) {
			provider.omitOID = true
		},
		"malformed selected oid": func(_ *testing.T, provider *tokenOIDCProvider) {
			provider.tokenOIDOverride = []string{"operator-oid"}
		},
		"missing ID token": func(_ *testing.T, provider *tokenOIDCProvider) {
			provider.omitIDToken = true
		},
		"token exchange failure": func(_ *testing.T, provider *tokenOIDCProvider) {
			provider.tokenStatus = http.StatusBadGateway
		},
	}

	for name, configure := range tests {
		t.Run(name, func(t *testing.T) {
			provider, _, _, ts, client, flowCookie := startBoundOIDCFlow(t)
			configure(t, provider)
			response := finishOIDCFlow(t, ts, client, flowCookie)
			defer response.Body.Close()
			if response.StatusCode != http.StatusUnauthorized {
				body, _ := io.ReadAll(response.Body)
				t.Fatalf("invalid provider token callback = %d, want 401: %s", response.StatusCode, body)
			}
			for _, cookie := range response.Cookies() {
				if isUISessionCookie(cookie) && cookie.MaxAge >= 0 {
					t.Fatalf("invalid token minted session cookie: %+v", cookie)
				}
			}
		})
	}
}

func TestUIOIDCCallbackConsumesStateAtomically(t *testing.T) {
	_, _, _, ts, client, flowCookie := startBoundOIDCFlow(t)
	callbackURL := ts.URL + "/ui/auth/oidc/callback?state=" + url.QueryEscape(flowCookie.Value) + "&code=test-code"

	start := make(chan struct{})
	statuses := make(chan int, 2)
	var callbacks sync.WaitGroup
	for range 2 {
		callbacks.Add(1)
		go func() {
			defer callbacks.Done()
			<-start
			request, _ := http.NewRequest(http.MethodGet, callbackURL, nil)
			request.Host = "agentbus.example.com"
			request.AddCookie(flowCookie)
			response, err := client.Do(request)
			if err != nil {
				t.Errorf("callback: %v", err)
				return
			}
			response.Body.Close()
			statuses <- response.StatusCode
		}()
	}
	close(start)
	callbacks.Wait()
	close(statuses)

	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[http.StatusSeeOther] != 1 || counts[http.StatusUnauthorized] != 1 {
		t.Fatalf("simultaneous callback statuses = %v, want one 303 and one 401", counts)
	}
}

func TestUIOIDCBoundsConcurrentTokenExchanges(t *testing.T) {
	gate := make(chan struct{})
	arrived := make(chan struct{}, maxUIOIDCExchanges+1)
	var tokenRequests atomic.Int32
	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
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
		case "/token":
			tokenRequests.Add(1)
			select {
			case arrived <- struct{}{}:
			default:
			}
			<-gate
			http.Error(w, "invalid code", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	closed := false
	closeGate := func() {
		if !closed {
			close(gate)
			closed = true
		}
	}
	defer closeGate()
	oidcLogin, err := NewBrowserOIDC(context.Background(), BrowserOIDCConfig{
		Issuer:       provider.URL,
		ClientID:     "agentbus-browser",
		ClientSecret: "test-secret",
		RedirectURL:  "https://agentbus.example.com/ui/auth/oidc/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := bus.Open(filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ts := httptest.NewServer((&Server{
		Bus:            b,
		AdminToken:     "admin-secret",
		UIOIDC:         oidcLogin,
		UIPublicOrigin: "https://agentbus.example.com",
	}).Handler())
	defer ts.Close()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	flows := make([]*http.Cookie, maxUIOIDCExchanges+1)
	for i := range flows {
		start, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/auth/oidc/start", nil)
		start.Host = "agentbus.example.com"
		start.Header.Set("Sec-Fetch-Site", "same-origin")
		start.Header.Set("Sec-Fetch-Mode", "navigate")
		start.Header.Set("Sec-Fetch-Dest", "document")
		response, err := client.Do(start)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		flows[i] = response.Cookies()[0]
	}
	callback := func(cookie *http.Cookie) int {
		request, _ := http.NewRequest(http.MethodGet, ts.URL+"/ui/auth/oidc/callback?state="+url.QueryEscape(cookie.Value)+"&code=invalid", nil)
		request.Host = "agentbus.example.com"
		request.AddCookie(cookie)
		response, err := client.Do(request)
		if err != nil {
			return 0
		}
		response.Body.Close()
		return response.StatusCode
	}
	firstStatuses := make(chan int, maxUIOIDCExchanges)
	for i := 0; i < maxUIOIDCExchanges; i++ {
		go func(cookie *http.Cookie) { firstStatuses <- callback(cookie) }(flows[i])
	}
	for i := 0; i < maxUIOIDCExchanges; i++ {
		select {
		case <-arrived:
		case <-time.After(2 * time.Second):
			t.Fatal("token exchanges did not reach provider")
		}
	}
	ninthStatus := make(chan int, 1)
	go func() { ninthStatus <- callback(flows[maxUIOIDCExchanges]) }()
	select {
	case status := <-ninthStatus:
		if status != http.StatusTooManyRequests {
			t.Fatalf("overflow callback status = %d, want 429", status)
		}
	case <-time.After(500 * time.Millisecond):
		closeGate()
		for i := 0; i < maxUIOIDCExchanges; i++ {
			<-firstStatuses
		}
		<-ninthStatus
		t.Fatalf("overflow exchange reached provider; requests = %d", tokenRequests.Load())
	}
	closeGate()
	for i := 0; i < maxUIOIDCExchanges; i++ {
		<-firstStatuses
	}
	requestsBeforeRetry := tokenRequests.Load()
	if status := callback(flows[maxUIOIDCExchanges]); status != http.StatusUnauthorized {
		t.Fatalf("retried callback status = %d, want provider failure 401", status)
	}
	if got := tokenRequests.Load(); got <= requestsBeforeRetry {
		t.Fatalf("retried callback did not reach token endpoint; requests %d -> %d", requestsBeforeRetry, got)
	}
}
