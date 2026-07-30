package httpapi

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jahwag/agentbus/internal/bus"
)

//go:embed ui/*.html ui/*.css
var uiAssets embed.FS

var uiTemplates = template.Must(template.ParseFS(uiAssets, "ui/*.html"))

type uiLoginView struct {
	Error string
}

type uiConversationMessage struct {
	bus.Message
	Data        string
	CanReply    bool
	ReplyTarget string
	CommandID   string
}

type uiConversationView struct {
	Messages      []uiConversationMessage
	MissingParent string
	Truncated     bool
}

const (
	uiBootstrapTTL  = 2 * time.Minute
	uiSessionTTL    = 8 * time.Hour
	maxUICodes      = 32
	maxUISessions   = 64
	uiSessionCookie = "agentbus_ui_session"
)

var errUICapacity = errors.New("agentbus: UI credential capacity reached")

type uiCredentialStore struct {
	mu       sync.Mutex
	randomMu sync.Mutex
	codes    map[[sha256.Size]byte]time.Time
	sessions map[[sha256.Size]byte]uiSession
	now      func() time.Time
	random   io.Reader
}

type uiSession struct {
	ExpiresAt time.Time
	Principal *bus.AuthenticatedPrincipal
}

func (s *Server) newUICredentialStore() *uiCredentialStore {
	now := s.uiNow
	if now == nil {
		now = time.Now
	}
	random := s.uiRandom
	if random == nil {
		random = rand.Reader
	}
	return &uiCredentialStore{
		codes:    make(map[[sha256.Size]byte]time.Time),
		sessions: make(map[[sha256.Size]byte]uiSession),
		now:      now,
		random:   random,
	}
}

func (s *uiCredentialStore) mintCode() (string, time.Time, error) {
	raw := make([]byte, 16)
	s.randomMu.Lock()
	defer s.randomMu.Unlock()
	if _, err := io.ReadFull(s.random, raw); err != nil {
		return "", time.Time{}, err
	}
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	hash := sha256.Sum256([]byte(code))
	now := s.now()
	expiresAt := now.Add(uiBootstrapTTL)

	s.mu.Lock()
	defer s.mu.Unlock()
	for existing, expiry := range s.codes {
		if !expiry.After(now) {
			delete(s.codes, existing)
		}
	}
	if len(s.codes) >= maxUICodes {
		return "", time.Time{}, errUICapacity
	}
	if _, collision := s.codes[hash]; collision {
		return "", time.Time{}, errors.New("agentbus: duplicate UI bootstrap code")
	}
	s.codes[hash] = expiresAt
	return code, expiresAt, nil
}

func (s *uiCredentialStore) exchangeCode(code, oldSession string) (string, error) {
	raw := make([]byte, 32)
	s.randomMu.Lock()
	_, randomErr := io.ReadFull(s.random, raw)
	s.randomMu.Unlock()
	if randomErr != nil {
		return "", randomErr
	}
	session := base64.RawURLEncoding.EncodeToString(raw)
	codeHash := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(code))))
	sessionHash := sha256.Sum256([]byte(session))
	oldHash := sha256.Sum256([]byte(oldSession))
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	codeExpiry, ok := s.codes[codeHash]
	if !ok || !codeExpiry.After(now) {
		return "", errors.New("invalid or expired UI login code")
	}
	_, replacing := s.sessions[oldHash]
	if len(s.sessions) >= maxUISessions && !replacing {
		return "", errUICapacity
	}
	delete(s.codes, codeHash)
	if oldSession != "" {
		delete(s.sessions, oldHash)
	}
	s.sessions[sessionHash] = uiSession{ExpiresAt: now.Add(uiSessionTTL)}
	return session, nil
}

func (s *uiCredentialStore) mintPrincipalSession(
	principal bus.AuthenticatedPrincipal,
	oldSession string,
) (string, uiSession, error) {
	raw := make([]byte, 32)
	s.randomMu.Lock()
	_, randomErr := io.ReadFull(s.random, raw)
	s.randomMu.Unlock()
	if randomErr != nil {
		return "", uiSession{}, randomErr
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	oldHash := sha256.Sum256([]byte(oldSession))
	now := s.now()
	expiry := now.Add(uiSessionTTL)
	if !principal.ExpiresAt.IsZero() && principal.ExpiresAt.Before(expiry) {
		expiry = principal.ExpiresAt
	}
	if !expiry.After(now) {
		return "", uiSession{}, errors.New("expired operator assertion")
	}
	session := uiSession{ExpiresAt: expiry, Principal: &principal}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	_, replacing := s.sessions[oldHash]
	if len(s.sessions) >= maxUISessions && !replacing {
		return "", uiSession{}, errUICapacity
	}
	if oldSession != "" {
		delete(s.sessions, oldHash)
	}
	s.sessions[hash] = session
	return token, session, nil
}

func (s *uiCredentialStore) session(token string) (uiSession, bool) {
	if token == "" {
		return uiSession{}, false
	}
	hash := sha256.Sum256([]byte(token))
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	session, ok := s.sessions[hash]
	return session, ok && session.ExpiresAt.After(now)
}

func (s *uiCredentialStore) revokeSession(session string) {
	if session == "" {
		return
	}
	hash := sha256.Sum256([]byte(session))
	s.mu.Lock()
	delete(s.sessions, hash)
	s.mu.Unlock()
}

func (s *uiCredentialStore) cleanupLocked(now time.Time) {
	for hash, expiry := range s.codes {
		if !expiry.After(now) {
			delete(s.codes, hash)
		}
	}
	for hash, session := range s.sessions {
		if !session.ExpiresAt.After(now) {
			delete(s.sessions, hash)
		}
	}
}

func (s *Server) handleUIBootstrap(store *uiCredentialStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authEnabled() || !loopbackHost(r.Host) {
			http.NotFound(w, r)
			return
		}
		if !decodeJSON(w, r, &struct{}{}) {
			return
		}
		code, expiresAt, err := store.mintCode()
		if err != nil {
			if errors.Is(err, errUICapacity) {
				writeError(w, http.StatusTooManyRequests, errors.New("too many active UI login codes"))
				return
			}
			writeBusError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"code": code, "expires_at": expiresAt.UTC().Format(time.RFC3339Nano),
		})
	}
}

func (s *Server) handleUILogin(store *uiCredentialStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.uiAvailable(r) {
			http.NotFound(w, r)
			return
		}
		if !s.sameOriginUIRequest(r) {
			writeError(w, http.StatusForbidden, errors.New("UI login refused"))
			return
		}
		form, ok := readUIForm(w, r, "code")
		if !ok {
			return
		}
		oldSession := ""
		if cookie, err := r.Cookie(uiSessionCookie); err == nil {
			oldSession = cookie.Value
		}
		session, err := store.exchangeCode(form.Get("code"), oldSession)
		if err != nil {
			if errors.Is(err, errUICapacity) {
				writeError(w, http.StatusTooManyRequests, errors.New("too many active UI sessions"))
				return
			}
			renderUITemplate(w, http.StatusUnauthorized, "login.html", uiLoginView{
				Error: "Invalid or expired code. Generate a new code and try again.",
			})
			return
		}
		s.setUISessionCookie(w, session)
		w.Header().Set("Location", "/ui/")
		w.WriteHeader(http.StatusSeeOther)
	}
}

func (s *Server) handleUIRoot(w http.ResponseWriter, r *http.Request) {
	if !s.uiAvailable(r) {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/ui/", http.StatusPermanentRedirect)
}

func (s *Server) handleUIDashboard(store *uiCredentialStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.uiAvailable(r) {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path != "/ui/" {
			http.NotFound(w, r)
			return
		}
		session, ok := s.authenticateUIRequest(w, r, store)
		if !ok {
			renderUITemplate(w, http.StatusOK, "login.html", uiLoginView{})
			return
		}
		if len(r.URL.Query()) != 0 {
			writeError(w, http.StatusBadRequest, errors.New("invalid overview query"))
			return
		}
		activity, err := s.Bus.Activity()
		if err != nil {
			writeBusError(w, err)
			return
		}
		view := struct {
			Activity bus.ActivityReport
			Operator string
			CanSend  bool
		}{Activity: activity}
		if session.Principal != nil {
			view.Operator = session.Principal.Name
			view.CanSend = true
		}
		renderUITemplate(w, http.StatusOK, "dashboard.html", view)
	}
}

func (s *Server) handleUIMessages(store *uiCredentialStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.uiAvailable(r) {
			http.NotFound(w, r)
			return
		}
		session, ok := s.authenticateUIRequest(w, r, store)
		if !ok {
			renderUITemplate(w, http.StatusOK, "login.html", uiLoginView{})
			return
		}
		beforeSeq, ok := parseUIBeforeSeq(w, r)
		if !ok {
			return
		}
		const pageSize = 50
		routes, err := s.Bus.RecentRoutes(beforeSeq, pageSize+1)
		if err != nil {
			writeBusError(w, err)
			return
		}
		roster, err := s.Bus.Roster()
		if err != nil {
			writeBusError(w, err)
			return
		}
		view := struct {
			Routes     []bus.RecentRoute
			Roster     []bus.RosterEntry
			HasOlder   bool
			NextBefore int64
			Operator   string
			CanSend    bool
			CommandID  string
		}{Routes: routes, Roster: roster}
		if session.Principal != nil {
			view.Operator = session.Principal.Name
			view.CanSend = true
			view.CommandID, err = store.newClientMessageID()
			if err != nil {
				writeBusError(w, err)
				return
			}
		}
		if len(view.Routes) > pageSize {
			view.Routes = view.Routes[:pageSize]
			view.HasOlder = true
			view.NextBefore = view.Routes[len(view.Routes)-1].Seq
		}
		renderUITemplate(w, http.StatusOK, "messages.html", view)
	}
}

func (s *Server) handleUIStyles(w http.ResponseWriter, r *http.Request) {
	if !s.uiAvailable(r) {
		http.NotFound(w, r)
		return
	}
	styles, err := uiAssets.ReadFile("ui/style.css")
	if err != nil {
		writeBusError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(styles)
}

func (s *Server) handleUIReveal(store *uiCredentialStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.uiAvailable(r) {
			http.NotFound(w, r)
			return
		}
		if !s.sameOriginUIRequest(r) {
			writeError(w, http.StatusForbidden, errors.New("UI reveal refused"))
			return
		}
		if _, ok := s.authenticateUIRequest(w, r, store); !ok {
			writeError(w, http.StatusUnauthorized, errors.New("UI session required"))
			return
		}
		form, ok := readUIForm(w, r, "message_id")
		if !ok {
			return
		}
		message, err := s.Bus.MessageContent(form.Get("message_id"))
		if errors.Is(err, bus.ErrMessageNotFound) {
			writeError(w, http.StatusNotFound, errors.New("retained message not found"))
			return
		}
		if err != nil {
			writeBusError(w, err)
			return
		}
		view := struct {
			Message bus.Message
			Data    string
		}{Message: message, Data: string(message.Data)}
		renderUITemplate(w, http.StatusOK, "reveal.html", view)
	}
}

func (s *Server) handleUIConversation(store *uiCredentialStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.uiAvailable(r) {
			http.NotFound(w, r)
			return
		}
		if !s.sameOriginUIRequest(r) {
			writeError(w, http.StatusForbidden, errors.New("UI conversation refused"))
			return
		}
		session, ok := s.authenticateUIRequest(w, r, store)
		if !ok {
			writeError(w, http.StatusUnauthorized, errors.New("UI session required"))
			return
		}
		form, ok := readUIForm(w, r, "message_id")
		if !ok {
			return
		}
		conversation, err := s.Bus.Conversation(form.Get("message_id"), 100)
		if errors.Is(err, bus.ErrMessageNotFound) {
			writeError(w, http.StatusNotFound, errors.New("retained conversation not found"))
			return
		}
		if err != nil {
			writeBusError(w, err)
			return
		}
		view := struct {
			Conversation uiConversationView
			Operator     string
		}{
			Conversation: uiConversationView{
				MissingParent: conversation.MissingParent,
				Truncated:     conversation.Truncated,
				Messages:      make([]uiConversationMessage, 0, len(conversation.Messages)),
			},
		}
		if session.Principal != nil {
			view.Operator = session.Principal.Name
		}
		for _, message := range conversation.Messages {
			messageView := uiConversationMessage{
				Message: message,
				Data:    string(message.Data),
			}
			if view.Operator != "" {
				messageView.CanReply = true
				messageView.ReplyTarget = message.From
				if message.From == view.Operator {
					messageView.ReplyTarget = message.To
				}
				messageView.CommandID, err = store.newClientMessageID()
				if err != nil {
					writeBusError(w, err)
					return
				}
			}
			view.Conversation.Messages = append(view.Conversation.Messages, messageView)
		}
		renderUITemplate(w, http.StatusOK, "conversation.html", view)
	}
}

func (s *Server) handleUISend(store *uiCredentialStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.uiAvailable(r) {
			http.NotFound(w, r)
			return
		}
		if !s.sameOriginUIRequest(r) {
			writeError(w, http.StatusForbidden, errors.New("UI send refused"))
			return
		}
		session, ok := s.authenticateUIRequest(w, r, store)
		if !ok || session.Principal == nil || session.Principal.Kind != "operator" {
			writeError(w, http.StatusForbidden, errors.New("externally authenticated operator session required"))
			return
		}
		form, ok := readUIFormWithLimit(
			w, r, maxRequestBytes, "to", "body", "reply_to", "client_message_id",
		)
		if !ok {
			return
		}
		if form.Get("to") == "*" {
			writeError(w, http.StatusBadRequest, errors.New("operator broadcast is not allowed"))
			return
		}
		clientID := form.Get("client_message_id")
		if !validUIClientMessageID(clientID) {
			writeError(w, http.StatusBadRequest, errors.New("invalid UI command identifier"))
			return
		}
		var replyTo *string
		if raw := strings.TrimSpace(form.Get("reply_to")); raw != "" {
			replyTo = &raw
		}
		_, err := s.Bus.SendAsOperator(*session.Principal, form.Get("to"), bus.SendOpts{
			Body:            form.Get("body"),
			ReplyTo:         replyTo,
			ClientMessageID: clientID,
		})
		if err != nil {
			writeBusError(w, err)
			return
		}
		w.Header().Set("Location", "/ui/messages")
		w.WriteHeader(http.StatusSeeOther)
	}
}

func (s *Server) handleUILogout(store *uiCredentialStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.uiAvailable(r) {
			http.NotFound(w, r)
			return
		}
		if !s.sameOriginUIRequest(r) {
			writeError(w, http.StatusForbidden, errors.New("UI logout refused"))
			return
		}
		if cookie, err := r.Cookie(uiSessionCookie); err == nil {
			store.revokeSession(cookie.Value)
		}
		s.clearUISessionCookie(w)
		if s.UIAssertionVerifier != nil {
			if s.UILogoutURL != "" {
				w.Header().Set("Location", s.UILogoutURL)
				w.WriteHeader(http.StatusSeeOther)
				return
			}
			renderUITemplate(w, http.StatusOK, "logout.html", struct{}{})
			return
		}
		w.Header().Set("Location", "/ui/")
		w.WriteHeader(http.StatusSeeOther)
	}
}

func (s *Server) uiAvailable(r *http.Request) bool {
	if !s.authEnabled() && s.UIAssertionVerifier == nil {
		return false
	}
	if s.UIPublicOrigin == "" {
		return loopbackHost(r.Host)
	}
	origin, err := url.Parse(s.UIPublicOrigin)
	return err == nil && origin.Scheme != "" && origin.Host != "" &&
		origin.Path == "" && r.Host == origin.Host
}

func (s *Server) authenticateUIRequest(
	w http.ResponseWriter,
	r *http.Request,
	store *uiCredentialStore,
) (uiSession, bool) {
	oldSession := ""
	if cookie, err := r.Cookie(uiSessionCookie); err == nil {
		oldSession = cookie.Value
		if session, ok := store.session(cookie.Value); ok {
			if session.Principal == nil {
				return session, true
			}
			if session.Principal.Kind == "operator" &&
				s.Bus.ValidatePrincipal(*session.Principal) == nil {
				return session, true
			}
			store.revokeSession(cookie.Value)
			s.clearUISessionCookie(w)
		}
	}
	if s.UIAssertionVerifier == nil {
		return uiSession{}, false
	}
	header := s.UIAssertionHeader
	if header == "" {
		header = "Cf-Access-Jwt-Assertion"
	}
	raw := strings.TrimSpace(r.Header.Get(header))
	if raw == "" {
		return uiSession{}, false
	}
	assertion, err := s.UIAssertionVerifier.Verify(r.Context(), raw)
	if err != nil {
		return uiSession{}, false
	}
	principal, err := s.Bus.AuthenticateExternal(
		assertion.Issuer,
		assertion.Subject,
		assertion.ExpiresAt,
	)
	if err != nil || principal.Kind != "operator" {
		return uiSession{}, false
	}
	token, session, err := store.mintPrincipalSession(principal, oldSession)
	if err != nil {
		return uiSession{}, false
	}
	s.setUISessionCookie(w, token)
	return session, true
}

func (s *uiCredentialStore) newClientMessageID() (string, error) {
	raw := make([]byte, 16)
	s.randomMu.Lock()
	_, err := io.ReadFull(s.random, raw)
	s.randomMu.Unlock()
	if err != nil {
		return "", err
	}
	return "operator-ui-" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func validUIClientMessageID(value string) bool {
	const prefix = "operator-ui-"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	encoded := strings.TrimPrefix(value, prefix)
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && len(raw) == 16 &&
		base64.RawURLEncoding.EncodeToString(raw) == encoded
}

func parseUIBeforeSeq(w http.ResponseWriter, r *http.Request) (int64, bool) {
	for key, values := range r.URL.Query() {
		if key != "before_seq" || len(values) != 1 {
			writeError(w, http.StatusBadRequest, errors.New("invalid dashboard pagination"))
			return 0, false
		}
	}
	raw := r.URL.Query().Get("before_seq")
	if raw == "" {
		return 0, true
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		writeError(w, http.StatusBadRequest, errors.New("invalid dashboard pagination"))
		return 0, false
	}
	return value, true
}

func renderUITemplate(w http.ResponseWriter, status int, name string, data any) {
	var rendered bytes.Buffer
	if err := uiTemplates.ExecuteTemplate(&rendered, name, data); err != nil {
		slog.Error("render AgentBus UI", "template", name, "err", err)
		writeError(w, http.StatusInternalServerError, errors.New("UI unavailable"))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(rendered.Bytes())
}

func (s *Server) setUISessionCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: uiSessionCookie, Value: value, Path: "/ui", HttpOnly: true,
		Secure: s.uiCookieSecure(), SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearUISessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: uiSessionCookie, Value: "", Path: "/ui", HttpOnly: true,
		Secure: s.uiCookieSecure(), SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}

func (s *Server) uiCookieSecure() bool {
	if s.UIPublicOrigin == "" {
		return false
	}
	origin, err := url.Parse(s.UIPublicOrigin)
	return err == nil && origin.Scheme == "https"
}

func (s *Server) sameOriginUIRequest(r *http.Request) bool {
	if !s.uiAvailable(r) {
		return false
	}
	expectedOrigin := s.UIPublicOrigin
	if expectedOrigin == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		expectedOrigin = scheme + "://" + r.Host
	}
	expectedOrigin = strings.TrimSuffix(expectedOrigin, "/")
	origin := r.Header.Get("Origin")
	fetchSite := r.Header.Get("Sec-Fetch-Site")
	fetchMode := r.Header.Get("Sec-Fetch-Mode")
	fetchDest := r.Header.Get("Sec-Fetch-Dest")
	fetchPresent := fetchSite != "" || fetchMode != "" || fetchDest != ""
	fetchSameOriginNavigation := fetchSite == "same-origin" &&
		fetchMode == "navigate" && fetchDest == "document"
	if origin == expectedOrigin {
		return !fetchPresent || fetchSameOriginNavigation
	}
	return (origin == "" || origin == "null") && fetchSameOriginNavigation
}

func readUIForm(w http.ResponseWriter, r *http.Request, allowedFields ...string) (mapForm, bool) {
	return readUIFormWithLimit(w, r, 4096, allowedFields...)
}

func readUIFormWithLimit(
	w http.ResponseWriter,
	r *http.Request,
	maxBytes int64,
	allowedFields ...string,
) (mapForm, bool) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		writeError(w, http.StatusUnsupportedMediaType, errors.New("Content-Type must be application/x-www-form-urlencoded"))
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid UI form"))
		return nil, false
	}
	allowed := make(map[string]bool, len(allowedFields))
	for _, field := range allowedFields {
		allowed[field] = true
	}
	for field, values := range r.PostForm {
		if !allowed[field] || len(values) != 1 {
			writeError(w, http.StatusBadRequest, errors.New("invalid UI form"))
			return nil, false
		}
	}
	if len(r.PostForm) != len(allowedFields) {
		writeError(w, http.StatusBadRequest, errors.New("invalid UI form"))
		return nil, false
	}
	return mapForm(r.PostForm), true
}

type mapForm map[string][]string

func (f mapForm) Get(key string) string {
	if values := f[key]; len(values) == 1 {
		return values[0]
	}
	return ""
}

func uiSecurityHeadersForPaths(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ui" || strings.HasPrefix(r.URL.Path, "/ui/") {
			setUISecurityHeaders(w)
		}
		next.ServeHTTP(w, r)
	})
}

func setUISecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}
