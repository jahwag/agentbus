// Package httpapi is a thin HTTP adapter over the bus delivery module.
// GET /wait is read-only; acknowledgement is a separate POST /ack.
package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jahwag/agentbus/internal/bus"
	"github.com/jahwag/agentbus/internal/oidcauth"
)

const (
	maxRequestBytes   = 256 * 1024
	maxWaitSeconds    = 290
	defaultAuditLimit = 100
	maxAuditLimit     = 1000
)

type Server struct {
	Bus *bus.Bus
	// AdminToken enables auth mode: every request needs a bearer token, agent
	// identity derives from the credential (name/from params carry no
	// authority), and admin ops require this exact token.
	AdminToken string
	// DisableUI removes every operator-dashboard route while leaving the agent
	// and administrator HTTP interfaces unchanged. The zero value keeps the UI
	// available in authenticated mode.
	DisableUI bool
	// UIAssertionVerifier enables trusted edge assertions, such as Cloudflare
	// Access JWTs, for operator sessions. External identities still have to be
	// explicitly bound to an operator mailbox in AgentBus.
	UIAssertionVerifier *oidcauth.Verifier
	UIAssertionHeader   string
	UIPublicOrigin      string
	UILogoutURL         string
	uiNow               func() time.Time
	uiRandom            io.Reader
}

type principalKey struct{}

type principal struct {
	Name                 string
	Kind                 string
	CredentialGeneration int64
	Admin                bool
}

func (s *Server) authEnabled() bool { return s.AdminToken != "" }

// withAuth authenticates the bearer token and stores the principal in the
// request context. In auth-off mode requests pass through unauthenticated.
func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authEnabled() {
			next(w, r)
			return
		}
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			writeError(w, http.StatusUnauthorized, errors.New("missing bearer token"))
			return
		}
		p := principal{Admin: equalToken(token, s.AdminToken)}
		if !p.Admin {
			authenticated, err := s.Bus.AuthenticatePrincipal(token)
			if err != nil {
				writeBusError(w, err)
				return
			}
			p.Name = authenticated.Name
			p.Kind = authenticated.Kind
			p.CredentialGeneration = authenticated.Generation
		}
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	}
}

func equalToken(a, b string) bool {
	aHash := sha256.Sum256([]byte(a))
	bHash := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aHash[:], bHash[:]) == 1
}

// identity resolves the acting name: the authenticated identity when a
// non-admin credential is present, otherwise the caller-claimed name.
func identity(r *http.Request, claimed string) string {
	if p, ok := r.Context().Value(principalKey{}).(principal); ok && !p.Admin {
		return p.Name
	}
	return claimed
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		if s.authEnabled() {
			if p, ok := r.Context().Value(principalKey{}).(principal); !ok || !p.Admin {
				writeError(w, http.StatusForbidden, errors.New("admin token required"))
				return
			}
		}
		next(w, r)
	})
}

func (s *Server) requireAgent(next http.HandlerFunc) http.HandlerFunc {
	return s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		if s.authEnabled() {
			if p, ok := r.Context().Value(principalKey{}).(principal); !ok || p.Admin || p.Kind != "agent" {
				writeError(w, http.StatusForbidden, errors.New("agent credential required"))
				return
			}
		}
		next(w, r)
	})
}

type sendRequest struct {
	From            string          `json:"from"`
	To              string          `json:"to"`
	Body            string          `json:"body"`
	Data            json.RawMessage `json:"data,omitempty"`
	ReplyTo         *string         `json:"reply_to,omitempty"`
	ClientMessageID string          `json:"client_message_id,omitempty"`
	AllowNew        bool            `json:"allow_new,omitempty"`
}

type ackRequest struct {
	Name       string `json:"name"`
	DeliveryID string `json:"delivery_id"`
}

type bindIdentityRequest struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

type unbindIdentityRequest struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /send", s.requireAgent(s.handleSend))
	mux.HandleFunc("GET /wait", s.requireAgent(s.handleWait))
	mux.HandleFunc("POST /ack", s.requireAgent(s.handleAck))
	mux.HandleFunc("GET /roster", s.withAuth(s.handleRoster))
	mux.HandleFunc("POST /mint", s.requireAdmin(s.handleMint))
	mux.HandleFunc("POST /bind-identity", s.requireAdmin(s.handleBindIdentity))
	mux.HandleFunc("POST /unbind-identity", s.requireAdmin(s.handleUnbindIdentity))
	mux.HandleFunc("POST /skip", s.requireAdmin(s.handleSkip))
	mux.HandleFunc("POST /retire", s.requireAdmin(s.handleRetire))
	mux.HandleFunc("POST /prune", s.requireAdmin(s.handlePrune))
	mux.HandleFunc("GET /backlog", s.requireAdmin(s.handleBacklog))
	mux.HandleFunc("GET /activity", s.requireAdmin(s.handleActivity))
	mux.HandleFunc("GET /audit", s.requireAdmin(s.handleAudit))
	if !s.DisableUI {
		uiStore := s.newUICredentialStore()
		mux.HandleFunc("POST /ui/bootstrap", s.requireAdmin(s.handleUIBootstrap(uiStore)))
		mux.HandleFunc("POST /ui/login", s.handleUILogin(uiStore))
		mux.HandleFunc("GET /ui", s.handleUIRoot)
		mux.HandleFunc("GET /ui/", s.handleUIDashboard(uiStore))
		mux.HandleFunc("GET /ui/messages", s.handleUIMessages(uiStore))
		mux.HandleFunc("GET /ui/style.css", s.handleUIStyles)
		mux.HandleFunc("POST /ui/reveal", s.handleUIReveal(uiStore))
		mux.HandleFunc("POST /ui/conversation", s.handleUIConversation(uiStore))
		mux.HandleFunc("POST /ui/send", s.handleUISend(uiStore))
		mux.HandleFunc("POST /ui/logout", s.handleUILogout(uiStore))
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if err := s.Bus.Ready(); err != nil {
			slog.Error("AgentBus readiness check failed", "err", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"code": "storage_unavailable", "error": "storage unavailable",
			})
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return NoStore(uiSecurityHeadersForPaths(ProtectLocalMode(mux, s.authEnabled())))
}

// NoStore prevents mailbox deliveries and newly minted credentials from being
// retained by browsers or intermediary caches.
func NoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// ProtectLocalMode blocks browser-origin and DNS-rebinding requests when
// identities are unauthenticated claims. It is also used around the sibling
// MCP endpoint by the daemon.
func ProtectLocalMode(next http.Handler, authEnabled bool) http.Handler {
	if authEnabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" || !loopbackHost(r.Host) {
			writeError(w, http.StatusForbidden, errors.New("auth-off mode accepts only non-browser loopback requests"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loopbackHost(hostport string) bool {
	host := hostport
	if parsed, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsed
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	return host == "localhost" || host == "agentbus.localhost" || (ip != nil && ip.IsLoopback())
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	var req sendRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	m, err := s.Bus.Send(identity(r, req.From), req.To, bus.SendOpts{
		Body:            req.Body,
		Data:            req.Data,
		ReplyTo:         req.ReplyTo,
		ClientMessageID: req.ClientMessageID,
		AllowNew:        req.AllowNew,
	})
	if err != nil {
		writeBusError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) handleWait(w http.ResponseWriter, r *http.Request) {
	for key, values := range r.URL.Query() {
		if (key != "name" && key != "timeout") || len(values) != 1 {
			writeError(w, http.StatusBadRequest, fmt.Errorf("unknown or repeated wait parameter %q", key))
			return
		}
	}
	name := identity(r, r.URL.Query().Get("name"))
	timeout := float64(maxWaitSeconds)
	if t := r.URL.Query().Get("timeout"); t != "" {
		parsed, err := strconv.ParseFloat(t, 64)
		if err != nil || parsed <= 0 || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid timeout %q", t))
			return
		}
		timeout = min(parsed, maxWaitSeconds)
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeout*float64(time.Second)))
	defer cancel()
	d, err := s.Bus.WaitDelivery(ctx, name)
	if err != nil {
		writeBusError(w, err)
		return
	}
	if d == nil {
		w.WriteHeader(http.StatusNoContent) // distinct timeout outcome, nothing acknowledged
		return
	}
	if p, ok := r.Context().Value(principalKey{}).(principal); ok && !p.Admin {
		if err := s.Bus.ValidatePrincipal(bus.AuthenticatedPrincipal{
			Name:       p.Name,
			Generation: p.CredentialGeneration,
		}); err != nil {
			writeBusError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleAck(w http.ResponseWriter, r *http.Request) {
	var req ackRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	_, err := s.Bus.Ack(identity(r, req.Name), req.DeliveryID)
	if err != nil {
		writeBusError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"acked": true, "delivery_id": req.DeliveryID})
}

func (s *Server) handleRoster(w http.ResponseWriter, _ *http.Request) {
	entries, err := s.Bus.Roster()
	if err != nil {
		writeBusError(w, err)
		return
	}
	if entries == nil {
		entries = []bus.RosterEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) handleBindIdentity(w http.ResponseWriter, r *http.Request) {
	var req bindIdentityRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.Bus.BindExternalIdentity(req.Name, req.Kind, req.Issuer, req.Subject); err != nil {
		writeBusError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"bound": true, "name": req.Name, "kind": req.Kind,
	})
}

func (s *Server) handleUnbindIdentity(w http.ResponseWriter, r *http.Request) {
	var req unbindIdentityRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.Bus.UnbindExternalIdentity(req.Issuer, req.Subject); err != nil {
		writeBusError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"unbound": true})
}

func (s *Server) handleMint(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	token, err := s.Bus.Mint(req.Name)
	if err != nil {
		writeBusError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": req.Name, "token": token})
}

func (s *Server) handleSkip(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		MessageID string `json:"message_id"`
		Reason    string `json:"reason"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.Bus.Skip(req.Name, req.MessageID, req.Reason); err != nil {
		writeBusError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRetire(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.Bus.Retire(req.Name, req.Reason); err != nil {
		writeBusError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handlePrune(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Before string `json:"before,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	before := time.Now().Add(-30 * 24 * time.Hour)
	if req.Before != "" {
		parsed, err := time.Parse(time.RFC3339, req.Before)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("before must be RFC3339"))
			return
		}
		before = parsed
	}
	result, err := s.Bus.Prune(before)
	if err != nil {
		writeBusError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleBacklog(w http.ResponseWriter, _ *http.Request) {
	report, err := s.Bus.Backlog()
	if err != nil {
		writeBusError(w, err)
		return
	}
	if report.Mailboxes == nil {
		report.Mailboxes = []bus.BacklogMailbox{}
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleActivity(w http.ResponseWriter, _ *http.Request) {
	report, err := s.Bus.Activity()
	if err != nil {
		writeBusError(w, err)
		return
	}
	if report.Mailboxes == nil {
		report.Mailboxes = []bus.ActivityMailbox{}
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	for key, values := range r.URL.Query() {
		if (key != "after_id" && key != "limit") || len(values) != 1 {
			writeError(w, http.StatusBadRequest, fmt.Errorf("unknown or repeated audit parameter %q", key))
			return
		}
	}
	afterID := int64(0)
	if raw := r.URL.Query().Get("after_id"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, errors.New("after_id must be a non-negative integer"))
			return
		}
		afterID = parsed
	}
	limit := defaultAuditLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > maxAuditLimit {
			writeError(w, http.StatusBadRequest, errors.New("limit must be between 1 and 1000"))
			return
		}
		limit = parsed
	}
	events, err := s.Bus.AuditEvents(afterID, limit)
	if err != nil {
		writeBusError(w, err)
		return
	}
	if events == nil {
		events = []bus.AuditEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

// GuardListen enforces the supported deployment topology: the daemon is
// loopback-only, with remote TLS terminated by a reverse proxy on the host.
// Bearer authentication does not make plaintext safe on a network interface.
func GuardListen(addr string, _ bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("refusing non-loopback listen address %s: bind loopback and use a TLS reverse proxy", addr)
}

// decodeJSON owns the mutation request contract in one place: JSON media
// type, bounded body, known fields only, and exactly one value.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, errors.New("Content-Type must be application/json"))
		return false
	}

	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeDecodeError(w, err)
		return false
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("request body must contain exactly one JSON value")
		}
		writeDecodeError(w, err)
		return false
	}
	return true
}

func writeDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, errors.New("request body too large"))
		return
	}
	writeError(w, http.StatusBadRequest, errors.New("invalid JSON request body"))
}

func writeBusError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	code := "internal_error"
	switch {
	case errors.Is(err, bus.ErrInvalidName),
		errors.Is(err, bus.ErrInvalidPrincipalKind),
		errors.Is(err, bus.ErrInvalidExternalID),
		errors.Is(err, bus.ErrInvalidClientMessageID),
		errors.Is(err, bus.ErrInvalidData),
		errors.Is(err, bus.ErrInvalidReplyTo),
		errors.Is(err, bus.ErrSelfSend),
		errors.Is(err, bus.ErrInvalidPagination),
		errors.Is(err, bus.ErrInvalidReason):
		status = http.StatusBadRequest
		code = "invalid_request"
	case errors.Is(err, bus.ErrMessageTooLarge):
		status = http.StatusRequestEntityTooLarge
		code = "message_too_large"
	case errors.Is(err, bus.ErrUnknownRecipient):
		status = http.StatusConflict
		code = "unknown_recipient"
	case errors.Is(err, bus.ErrDeliveryConflict):
		status = http.StatusConflict
		code = "delivery_conflict"
	case errors.Is(err, bus.ErrIdempotencyConflict):
		status = http.StatusConflict
		code = "idempotency_conflict"
	case errors.Is(err, bus.ErrExternalIdentityInUse):
		status = http.StatusConflict
		code = "external_identity_in_use"
	case errors.Is(err, bus.ErrPrincipalKindConflict):
		status = http.StatusConflict
		code = "principal_kind_conflict"
	case errors.Is(err, bus.ErrRetiredIdentity):
		status = http.StatusGone
		code = "retired_identity"
	case errors.Is(err, bus.ErrUnknownMessage):
		status = http.StatusNotFound
		code = "unknown_message"
	case errors.Is(err, bus.ErrBadToken):
		status = http.StatusUnauthorized
		code = "invalid_credential"
	case errors.Is(err, bus.ErrWaiterLimit):
		status = http.StatusTooManyRequests
		code = "resource_exhausted"
		w.Header().Set("Retry-After", "1")
	case errors.Is(err, bus.ErrBacklogLimit):
		status = http.StatusTooManyRequests
		code = "backlog_limit"
		w.Header().Set("Retry-After", "60")
	}
	if status == http.StatusInternalServerError {
		slog.Error("AgentBus request failed", "err", err)
		err = errors.New("internal server error")
	}
	writeJSON(w, status, map[string]string{"code": code, "error": err.Error()})
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"code": "request_error", "error": err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
