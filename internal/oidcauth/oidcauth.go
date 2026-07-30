package oidcauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

var (
	ErrInvalidToken        = errors.New("agentbus: invalid OIDC token")
	ErrVerifierUnavailable = errors.New("agentbus: OIDC verifier unavailable")
)

const (
	verifierHTTPTimeout  = 5 * time.Second
	jwksRefreshCooldown  = time.Minute
	maxOIDCResponseBytes = 1 << 20
)

type Assertion struct {
	Issuer    string
	Subject   string
	ExpiresAt time.Time
	Scopes    []string
	Roles     []string
}

type Verifier struct {
	issuer       string
	subjectClaim string
	requiredRole string
	verifier     *oidc.IDTokenVerifier
	transport    *cooldownTransport
}

func New(ctx context.Context, issuer, audience, subjectClaim, requiredRole string) (*Verifier, error) {
	transport := newCooldownTransport()
	ctx = oidc.ClientContext(ctx, &http.Client{
		Transport: transport,
		Timeout:   verifierHTTPTimeout,
	})
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	if subjectClaim == "" {
		subjectClaim = "sub"
	}
	return &Verifier{
		issuer:       issuer,
		subjectClaim: subjectClaim,
		requiredRole: requiredRole,
		verifier:     provider.Verifier(&oidc.Config{ClientID: audience}),
		transport:    transport,
	}, nil
}

func NewRemote(ctx context.Context, issuer, audience, jwksURL, subjectClaim, requiredRole string) *Verifier {
	transport := newCooldownTransport()
	ctx = oidc.ClientContext(ctx, &http.Client{
		Transport: transport,
		Timeout:   verifierHTTPTimeout,
	})
	if subjectClaim == "" {
		subjectClaim = "sub"
	}
	return &Verifier{
		issuer:       issuer,
		subjectClaim: subjectClaim,
		requiredRole: requiredRole,
		verifier: oidc.NewVerifier(
			issuer,
			oidc.NewRemoteKeySet(ctx, jwksURL),
			&oidc.Config{ClientID: audience},
		),
		transport: transport,
	}
}

func (v *Verifier) Verify(ctx context.Context, raw string) (Assertion, error) {
	failuresBefore := v.transport.failureCount()
	token, err := v.verifier.Verify(ctx, strings.TrimSpace(raw))
	if err != nil {
		if errors.Is(err, ErrVerifierUnavailable) {
			return Assertion{}, ErrVerifierUnavailable
		}
		if v.transport.failureCount() > failuresBefore {
			return Assertion{}, ErrVerifierUnavailable
		}
		return Assertion{}, ErrInvalidToken
	}
	var claims struct {
		OID   string   `json:"oid"`
		Scope string   `json:"scp"`
		Roles []string `json:"roles"`
	}
	if err := token.Claims(&claims); err != nil {
		return Assertion{}, ErrInvalidToken
	}
	subject := token.Subject
	if v.subjectClaim == "oid" {
		subject = claims.OID
	}
	if subject == "" || (v.requiredRole != "" && !contains(claims.Roles, v.requiredRole)) {
		return Assertion{}, ErrInvalidToken
	}
	return Assertion{
		Issuer: v.issuer, Subject: subject, ExpiresAt: token.Expiry,
		Scopes: strings.Fields(claims.Scope), Roles: claims.Roles,
	}, nil
}

type cachedResponse struct {
	status     string
	statusCode int
	header     http.Header
	body       []byte
	storedAt   time.Time
}

type cooldownTransport struct {
	base     http.RoundTripper
	cooldown time.Duration

	mu       sync.Mutex
	cache    map[string]cachedResponse
	failures uint64
}

func newCooldownTransport() *cooldownTransport {
	return &cooldownTransport{
		base:     http.DefaultTransport,
		cooldown: jwksRefreshCooldown,
		cache:    make(map[string]cachedResponse),
	}
}

func (t *cooldownTransport) failureCount() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.failures
}

func (t *cooldownTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodGet {
		return t.base.RoundTrip(request)
	}
	key := request.URL.String()
	now := time.Now()
	t.mu.Lock()
	cached, ok := t.cache[key]
	if ok && now.Sub(cached.storedAt) < t.cooldown {
		t.mu.Unlock()
		return responseFromCache(request, cached), nil
	}
	t.mu.Unlock()

	response, err := t.base.RoundTrip(request)
	if err != nil {
		t.recordFailure()
		return nil, errors.Join(ErrVerifierUnavailable, err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxOIDCResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.recordFailure()
		return nil, errors.Join(ErrVerifierUnavailable, readErr, closeErr)
	}
	if len(body) > maxOIDCResponseBytes {
		t.recordFailure()
		return nil, fmt.Errorf(
			"%w: OIDC response exceeds %d bytes",
			ErrVerifierUnavailable,
			maxOIDCResponseBytes,
		)
	}
	entry := cachedResponse{
		status:     response.Status,
		statusCode: response.StatusCode,
		header:     response.Header.Clone(),
		body:       body,
		storedAt:   now,
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		t.recordFailure()
		return nil, fmt.Errorf(
			"%w: OIDC endpoint returned %s",
			ErrVerifierUnavailable,
			response.Status,
		)
	}
	t.mu.Lock()
	t.cache[key] = entry
	t.mu.Unlock()
	return responseFromCache(request, entry), nil
}

func (t *cooldownTransport) recordFailure() {
	t.mu.Lock()
	t.failures++
	t.mu.Unlock()
}

func responseFromCache(request *http.Request, cached cachedResponse) *http.Response {
	return &http.Response{
		Status:        cached.status,
		StatusCode:    cached.statusCode,
		Header:        cached.header.Clone(),
		Body:          io.NopCloser(bytes.NewReader(cached.body)),
		ContentLength: int64(len(cached.body)),
		Request:       request,
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
