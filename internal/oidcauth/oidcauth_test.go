package oidcauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRemoteVerifierSupportsOIDScopesRolesAndAudience(t *testing.T) {
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	issuer := server.URL + "/issuer"
	verifier := NewRemote(
		context.Background(),
		issuer,
		"agentbus-api",
		server.URL,
		"oid",
		"AgentBus.Agent",
	)
	now := time.Now()
	token := signTestJWT(t, key, map[string]any{
		"iss": issuer,
		"aud": "agentbus-api",
		"sub": "unstable-subject",
		"oid": "stable-object-id",
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"scp": "mcp.read mcp.write",
		"roles": []string{
			"AgentBus.Agent",
		},
	})
	assertion, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if assertion.Subject != "stable-object-id" ||
		strings.Join(assertion.Scopes, " ") != "mcp.read mcp.write" ||
		len(assertion.Roles) != 1 || assertion.Roles[0] != "AgentBus.Agent" {
		t.Fatalf("assertion = %+v", assertion)
	}

	for name, claims := range map[string]map[string]any{
		"wrong audience": {
			"iss": issuer, "aud": "other-api", "sub": "subject", "oid": "object",
			"exp": now.Add(time.Hour).Unix(), "roles": []string{"AgentBus.Agent"},
		},
		"missing role": {
			"iss": issuer, "aud": "agentbus-api", "sub": "subject", "oid": "object",
			"exp": now.Add(time.Hour).Unix(), "roles": []string{"Other.Role"},
		},
		"missing oid": {
			"iss": issuer, "aud": "agentbus-api", "sub": "subject",
			"exp": now.Add(time.Hour).Unix(), "roles": []string{"AgentBus.Agent"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.Verify(
				context.Background(),
				signTestJWT(t, key, claims),
			); err != ErrInvalidToken {
				t.Fatalf("Verify error = %v", err)
			}
		})
	}
}

func TestRemoteVerifierThrottlesUnknownKeyRefreshAndClassifiesOutage(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": "different-key",
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}}
	var requests atomic.Int64
	var unavailable atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		if unavailable.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	issuer := server.URL + "/issuer"
	verifier := NewRemote(
		context.Background(),
		issuer,
		"agentbus-api",
		server.URL,
		"oid",
		"AgentBus.Agent",
	)
	now := time.Now()
	token := signTestJWT(t, key, map[string]any{
		"iss": issuer,
		"aud": "agentbus-api",
		"oid": "agent-oid",
		"exp": now.Add(time.Hour).Unix(),
		"roles": []string{
			"AgentBus.Agent",
		},
	})
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := verifier.Verify(context.Background(), token); err != ErrInvalidToken {
			t.Fatalf("unknown key attempt %d error = %v", attempt, err)
		}
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("unknown key attempts made %d upstream JWKS requests, want 1", got)
	}

	verifier.transport.cooldown = 0
	unavailable.Store(true)
	var outageErr error
	deadline := time.Now().Add(time.Second)
	for requests.Load() < 2 && time.Now().Before(deadline) {
		_, outageErr = verifier.Verify(context.Background(), token)
	}
	if requests.Load() < 2 {
		t.Fatal("JWKS verifier did not make the outage request")
	}
	if outageErr != ErrVerifierUnavailable {
		t.Fatalf("JWKS outage error = %v, want ErrVerifierUnavailable", outageErr)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("JWKS outage request count = %d, want 2", got)
	}
}

func signTestJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key", "typ": "JWT"})
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
