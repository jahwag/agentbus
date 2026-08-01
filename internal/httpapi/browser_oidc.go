package httpapi

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	uiOIDCFlowCookie       = "agentbus_ui_oidc"
	uiSecureOIDCFlowCookie = "__Host-agentbus_ui_oidc"
	uiOIDCFlowTTL          = 10 * time.Minute
	maxUIOIDCReplays       = 1024
	maxUIOIDCExchanges     = 8
	uiOIDCDiscoveryRetry   = 30 * time.Second
	uiOIDCDiscoveryTimeout = 10 * time.Second
)

type BrowserOIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	SubjectClaim string
	RequiredRole string
}

type browserOIDCFlow struct {
	verifier         string
	nonce            string
	oldSessionDigest [sha256.Size]byte
	replacesSession  bool
	expires          time.Time
}

type browserOIDCFlowPayload struct {
	Verifier         string `json:"v"`
	Nonce            string `json:"n"`
	OldSessionDigest string `json:"s,omitempty"`
	ExpiresUnix      int64  `json:"e"`
}

// BrowserOIDC owns the browser-facing OpenID Connect protocol. AgentBus
// authorization stays outside this module and continues to use explicit
// external identity bindings.
type BrowserOIDC struct {
	issuer          string
	clientID        string
	subjectClaim    string
	requiredRole    string
	verifier        *oidc.IDTokenVerifier
	client          *http.Client
	config          oauth2.Config
	providerMu      sync.Mutex
	providerRetryAt time.Time
	providerErr     error
	mu              sync.Mutex
	flowAEAD        cipher.AEAD
	usedFlows       map[[sha256.Size]byte]time.Time
	exchangeSlots   chan struct{}
	now             func() time.Time
	random          io.Reader
}

type browserOIDCIdentity struct {
	issuer    string
	subject   string
	expiresAt time.Time
}

func NewBrowserOIDC(_ context.Context, config BrowserOIDCConfig) (*BrowserOIDC, error) {
	config.Issuer = strings.TrimSpace(config.Issuer)
	config.ClientID = strings.TrimSpace(config.ClientID)
	config.RedirectURL = strings.TrimSpace(config.RedirectURL)
	if config.Issuer == "" || config.ClientID == "" || config.RedirectURL == "" {
		return nil, errors.New("browser OIDC issuer, client ID, and redirect URL are required")
	}
	if err := validateBrowserOIDCURL(config.Issuer, "issuer"); err != nil {
		return nil, err
	}
	if err := validateBrowserOIDCURL(config.RedirectURL, "redirect URL"); err != nil {
		return nil, err
	}
	config.SubjectClaim = strings.TrimSpace(config.SubjectClaim)
	if config.SubjectClaim == "" {
		config.SubjectClaim = "sub"
	}
	if config.SubjectClaim != "sub" && config.SubjectClaim != "oid" {
		return nil, errors.New("browser OIDC subject claim must be sub or oid")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	if len(config.Scopes) == 0 {
		config.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	} else if !containsString(config.Scopes, oidc.ScopeOpenID) {
		config.Scopes = append([]string{oidc.ScopeOpenID}, config.Scopes...)
	}
	flowKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, flowKey); err != nil {
		return nil, fmt.Errorf("generate browser OIDC flow key: %w", err)
	}
	block, err := aes.NewCipher(flowKey)
	if err != nil {
		return nil, fmt.Errorf("initialize browser OIDC flow cipher: %w", err)
	}
	flowAEAD, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize browser OIDC flow AEAD: %w", err)
	}
	return &BrowserOIDC{
		issuer:       config.Issuer,
		clientID:     config.ClientID,
		subjectClaim: config.SubjectClaim,
		requiredRole: config.RequiredRole,
		client:       client,
		config: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURL,
			Scopes:       config.Scopes,
		},
		flowAEAD:      flowAEAD,
		usedFlows:     make(map[[sha256.Size]byte]time.Time),
		exchangeSlots: make(chan struct{}, maxUIOIDCExchanges),
		now:           time.Now,
		random:        rand.Reader,
	}, nil
}

func (o *BrowserOIDC) ensureProvider(_ context.Context) error {
	o.providerMu.Lock()
	defer o.providerMu.Unlock()
	if o.verifier != nil {
		return nil
	}
	now := o.now()
	if o.providerErr != nil && now.Before(o.providerRetryAt) {
		return o.providerErr
	}
	discoveryCtx, cancel := context.WithTimeout(context.Background(), uiOIDCDiscoveryTimeout)
	defer cancel()
	provider, err := oidc.NewProvider(oidc.ClientContext(discoveryCtx, o.client), o.issuer)
	if err == nil {
		endpoint := provider.Endpoint()
		var metadata struct {
			JWKSURI string `json:"jwks_uri"`
		}
		err = provider.Claims(&metadata)
		if err == nil {
			for label, raw := range map[string]string{
				"authorization endpoint": endpoint.AuthURL,
				"token endpoint":         endpoint.TokenURL,
				"JWKS endpoint":          metadata.JWKSURI,
			} {
				if err = validateBrowserOIDCURL(raw, label); err != nil {
					break
				}
			}
		}
		if err == nil {
			o.verifier = provider.Verifier(&oidc.Config{ClientID: o.clientID})
			o.config.Endpoint = endpoint
			o.providerErr = nil
			o.providerRetryAt = time.Time{}
			return nil
		}
	}
	o.providerErr = err
	o.providerRetryAt = now.Add(uiOIDCDiscoveryRetry)
	return err
}

func validateBrowserOIDCURL(raw, label string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("browser OIDC %s must be an absolute HTTPS URL", label)
	}
	if parsed.Scheme == "https" || (parsed.Scheme == "http" && loopbackHost(parsed.Host)) {
		return nil
	}
	return fmt.Errorf("browser OIDC %s must use HTTPS except on loopback", label)
}

func (o *BrowserOIDC) beginExchange() (func(), bool) {
	select {
	case o.exchangeSlots <- struct{}{}:
		return func() { <-o.exchangeSlots }, true
	default:
		return nil, false
	}
}

func (o *BrowserOIDC) exchange(ctx context.Context, flow browserOIDCFlow, code string) (browserOIDCIdentity, error) {
	if err := o.ensureProvider(ctx); err != nil {
		return browserOIDCIdentity{}, err
	}
	ctx = oidc.ClientContext(ctx, o.client)
	token, err := o.config.Exchange(ctx, code, oauth2.VerifierOption(flow.verifier))
	if err != nil {
		return browserOIDCIdentity{}, err
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return browserOIDCIdentity{}, errors.New("identity provider omitted ID token")
	}
	idToken, err := o.verifier.Verify(ctx, rawIDToken)
	if err != nil || idToken.Nonce != flow.nonce {
		return browserOIDCIdentity{}, errors.New("invalid OIDC identity")
	}
	var party struct {
		AuthorizedParty string `json:"azp"`
	}
	if err := idToken.Claims(&party); err != nil ||
		(party.AuthorizedParty != "" && party.AuthorizedParty != o.clientID) ||
		(len(idToken.Audience) > 1 && party.AuthorizedParty == "") {
		return browserOIDCIdentity{}, errors.New("invalid OIDC authorized party")
	}
	subject := idToken.Subject
	if o.subjectClaim == "oid" {
		var claims struct {
			OID string `json:"oid"`
		}
		if err := idToken.Claims(&claims); err != nil {
			return browserOIDCIdentity{}, errors.New("invalid OIDC subject claim")
		}
		subject = claims.OID
	}
	if subject == "" {
		return browserOIDCIdentity{}, errors.New("OIDC identity is not authorized")
	}
	if o.requiredRole != "" {
		var claims struct {
			Roles []string `json:"roles"`
		}
		if err := idToken.Claims(&claims); err != nil || !containsString(claims.Roles, o.requiredRole) {
			return browserOIDCIdentity{}, errors.New("OIDC identity is not authorized")
		}
	}
	return browserOIDCIdentity{issuer: o.issuer, subject: subject, expiresAt: idToken.Expiry}, nil
}

func (o *BrowserOIDC) consumeFlow(state string) (browserOIDCFlow, bool) {
	var flow browserOIDCFlow
	raw, err := base64.RawURLEncoding.Strict().DecodeString(state)
	if err != nil || len(raw) <= o.flowAEAD.NonceSize() || len(raw) > 2048 {
		return flow, false
	}
	plaintext, err := o.flowAEAD.Open(nil, raw[:o.flowAEAD.NonceSize()], raw[o.flowAEAD.NonceSize():], nil)
	if err != nil {
		return flow, false
	}
	var payload browserOIDCFlowPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return flow, false
	}
	now := o.now()
	flow.verifier = payload.Verifier
	flow.nonce = payload.Nonce
	flow.expires = time.Unix(payload.ExpiresUnix, 0)
	if flow.verifier == "" || flow.nonce == "" || !flow.expires.After(now) {
		return browserOIDCFlow{}, false
	}
	if payload.OldSessionDigest != "" {
		oldDigest, err := base64.RawURLEncoding.DecodeString(payload.OldSessionDigest)
		if err != nil || len(oldDigest) != sha256.Size {
			return browserOIDCFlow{}, false
		}
		copy(flow.oldSessionDigest[:], oldDigest)
		flow.replacesSession = true
	}
	digest := sha256.Sum256(raw)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cleanupLocked(now)
	if _, used := o.usedFlows[digest]; used {
		return browserOIDCFlow{}, false
	}
	if len(o.usedFlows) >= maxUIOIDCReplays {
		var oldestDigest [sha256.Size]byte
		var oldestExpiry time.Time
		for existingDigest, expiry := range o.usedFlows {
			if oldestExpiry.IsZero() || expiry.Before(oldestExpiry) {
				oldestDigest = existingDigest
				oldestExpiry = expiry
			}
		}
		delete(o.usedFlows, oldestDigest)
	}
	o.usedFlows[digest] = flow.expires
	return flow, true
}

func (o *BrowserOIDC) start(ctx context.Context, _ string, oldSession string) (location, state string, err error) {
	if err := o.ensureProvider(ctx); err != nil {
		return "", "", err
	}
	nonce, err := randomOIDCValue(o.random, 32)
	if err != nil {
		return "", "", err
	}
	verifier := oauth2.GenerateVerifier()
	now := o.now()
	payload := browserOIDCFlowPayload{
		Verifier:    verifier,
		Nonce:       nonce,
		ExpiresUnix: now.Add(uiOIDCFlowTTL).Unix(),
	}
	if oldSession != "" {
		digest := sha256.Sum256([]byte(oldSession))
		payload.OldSessionDigest = base64.RawURLEncoding.EncodeToString(digest[:])
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}
	sealNonce := make([]byte, o.flowAEAD.NonceSize())
	if _, err := io.ReadFull(o.random, sealNonce); err != nil {
		return "", "", err
	}
	state = base64.RawURLEncoding.EncodeToString(o.flowAEAD.Seal(sealNonce, sealNonce, plaintext, nil))
	return o.config.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	), state, nil
}

func (o *BrowserOIDC) cleanupLocked(now time.Time) {
	for digest, expiry := range o.usedFlows {
		if !expiry.After(now) {
			delete(o.usedFlows, digest)
		}
	}
}

func randomOIDCValue(random io.Reader, size int) (string, error) {
	raw := make([]byte, size)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
