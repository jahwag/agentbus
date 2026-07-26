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
	sessions map[[sha256.Size]byte]time.Time
	now      func() time.Time
	random   io.Reader
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
		sessions: make(map[[sha256.Size]byte]time.Time),
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
	s.sessions[sessionHash] = now.Add(uiSessionTTL)
	return session, nil
}

func (s *uiCredentialStore) validSession(session string) bool {
	if session == "" {
		return false
	}
	hash := sha256.Sum256([]byte(session))
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	expiry, ok := s.sessions[hash]
	return ok && expiry.After(now)
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
	for hash, expiry := range s.sessions {
		if !expiry.After(now) {
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
		if !sameOriginUIRequest(r) {
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
		http.SetCookie(w, &http.Cookie{
			Name: uiSessionCookie, Value: session, Path: "/ui", HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
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
		cookie, err := r.Cookie(uiSessionCookie)
		if err != nil || !store.validSession(cookie.Value) {
			if err == nil {
				clearUISessionCookie(w)
			}
			renderUITemplate(w, http.StatusOK, "login.html", uiLoginView{})
			return
		}

		beforeSeq, ok := parseUIBeforeSeq(w, r)
		if !ok {
			return
		}
		activity, err := s.Bus.Activity()
		if err != nil {
			writeBusError(w, err)
			return
		}
		const pageSize = 50
		routes, err := s.Bus.RecentRoutes(beforeSeq, pageSize+1)
		if err != nil {
			writeBusError(w, err)
			return
		}
		view := struct {
			Activity   bus.ActivityReport
			Routes     []bus.RecentRoute
			HasOlder   bool
			NextBefore int64
		}{Activity: activity, Routes: routes}
		if len(view.Routes) > pageSize {
			view.Routes = view.Routes[:pageSize]
			view.HasOlder = true
			view.NextBefore = view.Routes[len(view.Routes)-1].Seq
		}
		renderUITemplate(w, http.StatusOK, "dashboard.html", view)
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
		if !sameOriginUIRequest(r) {
			writeError(w, http.StatusForbidden, errors.New("UI reveal refused"))
			return
		}
		cookie, err := r.Cookie(uiSessionCookie)
		if err != nil || !store.validSession(cookie.Value) {
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

func (s *Server) handleUILogout(store *uiCredentialStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.uiAvailable(r) {
			http.NotFound(w, r)
			return
		}
		if !sameOriginUIRequest(r) {
			writeError(w, http.StatusForbidden, errors.New("UI logout refused"))
			return
		}
		if cookie, err := r.Cookie(uiSessionCookie); err == nil {
			store.revokeSession(cookie.Value)
		}
		clearUISessionCookie(w)
		w.Header().Set("Location", "/ui/")
		w.WriteHeader(http.StatusSeeOther)
	}
}

func (s *Server) uiAvailable(r *http.Request) bool {
	return s.authEnabled() && loopbackHost(r.Host)
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

func clearUISessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: uiSessionCookie, Value: "", Path: "/ui", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}

func sameOriginUIRequest(r *http.Request) bool {
	if !loopbackHost(r.Host) {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	origin := r.Header.Get("Origin")
	fetchSite := r.Header.Get("Sec-Fetch-Site")
	fetchMode := r.Header.Get("Sec-Fetch-Mode")
	fetchDest := r.Header.Get("Sec-Fetch-Dest")
	fetchPresent := fetchSite != "" || fetchMode != "" || fetchDest != ""
	fetchSameOriginNavigation := fetchSite == "same-origin" &&
		fetchMode == "navigate" && fetchDest == "document"
	if origin == scheme+"://"+r.Host {
		return !fetchPresent || fetchSameOriginNavigation
	}
	return (origin == "" || origin == "null") && fetchSameOriginNavigation
}

func readUIForm(w http.ResponseWriter, r *http.Request, allowedFields ...string) (mapForm, bool) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		writeError(w, http.StatusUnsupportedMediaType, errors.New("Content-Type must be application/x-www-form-urlencoded"))
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
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
