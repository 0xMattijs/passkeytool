package server

import (
	"crypto/rand"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/0xMattijs/passkeytool/internal/aaguid"
	"github.com/0xMattijs/passkeytool/internal/attestation"
	"github.com/0xMattijs/passkeytool/internal/store"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

//go:embed web
var webFS embed.FS

const (
	sessionCookie = "pk_sid"
	sessionTTL    = 24 * time.Hour
)

type Server struct {
	wa      *webauthn.WebAuthn
	store   *store.Store
	cfg     Config
	secure  bool
	mu      sync.Mutex
	session map[string]*session
}

// session holds login state and in-flight ceremony state for one browser.
type session struct {
	UserID   []byte
	Expires  time.Time
	Reg      *webauthn.SessionData
	RegUser  *store.User // pending user (new account) or copy of the current user
	RegIsNew bool
	Logins   map[string]*webauthn.SessionData // pending logins keyed by challenge
}

func New(cfg Config, store *store.Store) (*Server, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPName,
		RPOrigins:     cfg.Origins,
	})
	if err != nil {
		return nil, err
	}
	return &Server{
		wa:      wa,
		store:   store,
		cfg:     cfg,
		secure:  strings.HasPrefix(cfg.Origins[0], "https://"),
		session: map[string]*session{},
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /", http.FileServer(http.FS(static)))

	mux.HandleFunc("GET /.well-known/webauthn", s.handleRelatedOrigins)
	mux.HandleFunc("GET /api/config", s.handleConfig)
	mux.HandleFunc("GET /api/me", s.handleMe)
	mux.HandleFunc("GET /api/codegen/targets", s.handleCodegenTargets)
	mux.HandleFunc("POST /api/codegen", s.handleCodegen)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("POST /api/register/begin", s.handleRegisterBegin)
	mux.HandleFunc("POST /api/register/finish", s.handleRegisterFinish)
	mux.HandleFunc("POST /api/login/begin", s.handleLoginBegin)
	mux.HandleFunc("POST /api/login/finish", s.handleLoginFinish)
	mux.HandleFunc("DELETE /api/credentials/{id}", s.handleDeleteCredential)
	mux.HandleFunc("PATCH /api/credentials/{id}", s.handleRenameCredential)
	mux.HandleFunc("DELETE /api/me", s.handleDeleteAccount)
	var h http.Handler = mux
	if s.cfg.RateLimit > 0 {
		h = newRateLimiter(s.cfg.RateLimit, s.cfg.TrustProxy).wrap(h)
	}
	return logRequests(limitBodies(h))
}

var errTooManyRequests = errors.New("too many requests: wait a minute and try again")

// ---------- sessions ----------

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, sess := range s.session {
		if now.After(sess.Expires) {
			delete(s.session, id)
		}
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if sess, ok := s.session[c.Value]; ok {
			return sess
		}
	}
	if len(s.session) >= maxSessions {
		// Evict the session closest to expiring, which is the oldest one.
		var oldest string
		for id, sess := range s.session {
			if oldest == "" || sess.Expires.Before(s.session[oldest].Expires) {
				oldest = id
			}
		}
		delete(s.session, oldest)
	}
	id := randomString(32)
	sess := &session{Expires: now.Add(sessionTTL)}
	s.session[id] = sess
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	return sess
}

// withSession runs fn while holding the session lock.
func (s *Server) withSession(sess *session, fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}

func (s *Server) currentUser(sess *session) (*store.User, error) {
	var uid []byte
	s.withSession(sess, func() { uid = sess.UserID })
	if uid == nil {
		return nil, nil
	}
	var user *store.User
	err := s.store.View(func(d *store.Data) error {
		user = d.UserByID(uid)
		return nil
	})
	if user == nil && err == nil {
		// Account was deleted (perhaps from the CLI); log out.
		s.withSession(sess, func() { sess.UserID = nil })
	}
	return user, err
}

// ---------- handlers ----------

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"rpId":    s.cfg.RPID,
		"rpName":  s.cfg.RPName,
		"origins": s.cfg.Origins,
		"notice":  s.cfg.Notice,
	})
}

// handleRelatedOrigins serves the Related Origin Requests document, which
// lets the other configured origins use this RP ID. Browsers fetch it from
// https://<rp-id>/.well-known/webauthn.
func (s *Server) handleRelatedOrigins(w http.ResponseWriter, r *http.Request) {
	doc, err := s.wa.RelatedOrigins()
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("no related origins document: %w", err))
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := s.getSession(w, r)
	user, err := s.currentUser(sess)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if user == nil {
		writeJSON(w, http.StatusOK, map[string]any{"user": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": userView(user)})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := s.getSession(w, r)
	s.withSession(sess, func() { sess.UserID = nil })
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type registerBeginReq struct {
	Username         string   `json:"username"`
	DisplayName      string   `json:"displayName"`
	ResidentKey      string   `json:"residentKey"`
	UserVerification string   `json:"userVerification"`
	Attachment       string   `json:"attachment"`
	Attestation      string   `json:"attestation"`
	Hints            []string `json:"hints"`
	ExcludeExisting  *bool    `json:"excludeExisting"`
	CredProps        bool     `json:"credProps"`
	PRF              bool     `json:"prf"`
}

func (s *Server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var req registerBeginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	sess := s.getSession(w, r)
	current, err := s.currentUser(sess)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var user *store.User
	isNew := false
	if current != nil {
		// Signed in: add another passkey to the current account.
		user = current
		if s.cfg.MaxPasskeys > 0 && len(user.Credentials) >= s.cfg.MaxPasskeys {
			writeError(w, http.StatusForbidden, fmt.Errorf("an account can hold at most %d passkeys on this server", s.cfg.MaxPasskeys))
			return
		}
	} else {
		req.Username = strings.TrimSpace(req.Username)
		if req.Username == "" {
			writeError(w, http.StatusBadRequest, errors.New("username is required"))
			return
		}
		if len([]rune(req.Username)) > maxNameLen || len([]rune(req.DisplayName)) > maxNameLen {
			writeError(w, http.StatusBadRequest, fmt.Errorf("username and display name can be at most %d characters", maxNameLen))
			return
		}
		var taken, full bool
		_ = s.store.View(func(d *store.Data) error {
			taken = d.UserByName(req.Username) != nil
			full = s.cfg.MaxUsers > 0 && len(d.Users) >= s.cfg.MaxUsers
			return nil
		})
		if full {
			writeError(w, http.StatusForbidden, fmt.Errorf("this server is full (%d accounts); try again after it resets", s.cfg.MaxUsers))
			return
		}
		if taken {
			writeError(w, http.StatusConflict, fmt.Errorf("username %q is taken; sign in to add a passkey to it", req.Username))
			return
		}
		display := strings.TrimSpace(req.DisplayName)
		if display == "" {
			display = req.Username
		}
		user = &store.User{ID: randomBytes(32), Name: req.Username, DisplayName: display}
		isNew = true
	}

	sel := protocol.AuthenticatorSelection{
		AuthenticatorAttachment: protocol.AuthenticatorAttachment(req.Attachment),
		ResidentKey:             protocol.ResidentKeyRequirement(orDefault(req.ResidentKey, "required")),
		UserVerification:        protocol.UserVerificationRequirement(orDefault(req.UserVerification, "preferred")),
	}
	if sel.ResidentKey == protocol.ResidentKeyRequirementRequired {
		sel.RequireResidentKey = protocol.ResidentKeyRequired()
	}
	opts := []webauthn.RegistrationOption{
		webauthn.WithAuthenticatorSelection(sel),
		webauthn.WithConveyancePreference(protocol.ConveyancePreference(orDefault(req.Attestation, "none"))),
	}
	if req.ExcludeExisting == nil || *req.ExcludeExisting {
		var excl []protocol.CredentialDescriptor
		for _, c := range user.Credentials {
			excl = append(excl, c.Descriptor())
		}
		opts = append(opts, webauthn.WithExclusions(excl))
	}
	if len(req.Hints) > 0 {
		hints := make([]protocol.PublicKeyCredentialHints, len(req.Hints))
		for i, h := range req.Hints {
			hints[i] = protocol.PublicKeyCredentialHints(h)
		}
		opts = append(opts, webauthn.WithPublicKeyCredentialHints(hints))
	}
	var exts []webauthn.ExtensionOption
	if req.CredProps {
		exts = append(exts, webauthn.WithExtensionCredProps())
	}
	if req.PRF {
		exts = append(exts, webauthn.WithExtensionPRFSupport())
	}
	if len(exts) > 0 {
		opts = append(opts, webauthn.WithExtensions(exts...))
	}

	creation, sd, err := s.wa.BeginRegistration(user, opts...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.withSession(sess, func() {
		sess.Reg, sess.RegUser, sess.RegIsNew = sd, user, isNew
	})
	writeJSON(w, http.StatusOK, creation)
}

func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	sess := s.getSession(w, r)
	var (
		sd    *webauthn.SessionData
		user  *store.User
		isNew bool
	)
	s.withSession(sess, func() {
		sd, user, isNew = sess.Reg, sess.RegUser, sess.RegIsNew
		sess.Reg, sess.RegUser = nil, nil
	})
	if sd == nil || user == nil {
		writeError(w, http.StatusBadRequest, errors.New("no registration in progress"))
		return
	}

	cred, err := s.wa.FinishRegistration(user, *sd, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, describeErr(err))
		return
	}
	stored := store.Credential{
		Credential: *cred,
		Nickname:   truncate(strings.TrimSpace(r.URL.Query().Get("nickname")), maxNickname),
		CreatedAt:  time.Now().UTC(),
	}

	var saved *store.User
	err = s.store.Update(func(d *store.Data) error {
		if _, i := d.FindCredential(cred.ID); i >= 0 {
			return errors.New("credential already registered")
		}
		if isNew {
			if d.UserByName(user.Name) != nil {
				return fmt.Errorf("username %q was taken in the meantime", user.Name)
			}
			if s.cfg.MaxUsers > 0 && len(d.Users) >= s.cfg.MaxUsers {
				return fmt.Errorf("this server is full (%d accounts); try again after it resets", s.cfg.MaxUsers)
			}
			user.CreatedAt = time.Now().UTC()
			user.Credentials = []store.Credential{stored}
			d.Users = append(d.Users, user)
			saved = user
			return nil
		}
		u := d.UserByID(user.ID)
		if u == nil {
			return errors.New("account no longer exists")
		}
		if s.cfg.MaxPasskeys > 0 && len(u.Credentials) >= s.cfg.MaxPasskeys {
			return fmt.Errorf("an account can hold at most %d passkeys on this server", s.cfg.MaxPasskeys)
		}
		u.Credentials = append(u.Credentials, stored)
		saved = u
		return nil
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.withSession(sess, func() { sess.UserID = saved.ID })
	log.Printf("registered credential %s for user %q (aaguid %s)", store.EncodeID(cred.ID), saved.Name, aaguid.Format(cred.Authenticator.AAGUID))
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       userView(saved),
		"credential": credentialView(stored),
	})
}

type loginBeginReq struct {
	Username         string   `json:"username"`
	UserVerification string   `json:"userVerification"`
	Mediation        string   `json:"mediation"`
	PRFSalt          string   `json:"prfSalt"` // evaluate the PRF extension with this salt
	Hints            []string `json:"hints"`
}

func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req loginBeginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	sess := s.getSession(w, r)
	opts := []webauthn.LoginOption{
		webauthn.WithUserVerification(protocol.UserVerificationRequirement(orDefault(req.UserVerification, "preferred"))),
	}
	if len(req.Hints) > 0 {
		hints := make([]protocol.PublicKeyCredentialHints, len(req.Hints))
		for i, h := range req.Hints {
			hints[i] = protocol.PublicKeyCredentialHints(h)
		}
		opts = append(opts, webauthn.WithAssertionPublicKeyCredentialHints(hints))
	}
	if req.PRFSalt != "" {
		// The browser hashes the salt with a WebAuthn-specific prefix before
		// passing it to the authenticator, so any bytes work here.
		opts = append(opts, webauthn.WithAssertionExtensions(
			webauthn.WithExtensionPRF(protocol.PRFValues{First: []byte(req.PRFSalt)}),
		))
	}

	var (
		assertion *protocol.CredentialAssertion
		sd        *webauthn.SessionData
		err       error
	)
	username := strings.TrimSpace(req.Username)
	if username == "" {
		// Discoverable (usernameless) login.
		assertion, sd, err = s.wa.BeginDiscoverableMediatedLogin(protocol.CredentialMediationRequirement(req.Mediation), opts...)
	} else {
		var user *store.User
		_ = s.store.View(func(d *store.Data) error {
			user = d.UserByName(username)
			return nil
		})
		if user == nil || len(user.Credentials) == 0 {
			writeError(w, http.StatusNotFound, fmt.Errorf("no user %q with passkeys", username))
			return
		}
		assertion, sd, err = s.wa.BeginMediatedLogin(user, protocol.CredentialMediationRequirement(req.Mediation), opts...)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.withSession(sess, func() {
		if sess.Logins == nil || len(sess.Logins) > 16 {
			sess.Logins = map[string]*webauthn.SessionData{}
		}
		sess.Logins[sd.Challenge] = sd
	})
	writeJSON(w, http.StatusOK, assertion)
}

func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	sess := s.getSession(w, r)
	parsed, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, describeErr(err))
		return
	}
	// Conditional and explicit sign-ins can be pending at the same time;
	// pick the one this response answers.
	var sd *webauthn.SessionData
	s.withSession(sess, func() {
		challenge := parsed.Response.CollectedClientData.Challenge
		sd = sess.Logins[challenge]
		delete(sess.Logins, challenge)
	})
	if sd == nil {
		writeError(w, http.StatusBadRequest, errors.New("unknown or expired challenge: the server did not issue it for a pending sign-in"))
		return
	}

	var snapshot *store.Data
	if err := s.store.View(func(d *store.Data) error { snapshot = d; return nil }); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	lookup := func(rawID, userHandle []byte) (webauthn.User, error) {
		u, _ := snapshot.FindCredential(rawID)
		if u == nil {
			return nil, fmt.Errorf("unknown credential %s", store.EncodeID(rawID))
		}
		if len(userHandle) > 0 && string(userHandle) != string(u.ID) {
			return nil, errors.New("user handle does not match credential owner")
		}
		return u, nil
	}

	var cred *webauthn.Credential
	if len(sd.UserID) == 0 {
		_, cred, err = s.wa.ValidatePasskeyLogin(lookup, *sd, parsed)
	} else {
		u := snapshot.UserByID(sd.UserID)
		if u == nil {
			writeError(w, http.StatusBadRequest, errors.New("account no longer exists"))
			return
		}
		cred, err = s.wa.ValidateLogin(u, *sd, parsed)
	}
	if err != nil {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("credential %s: %w", parsed.ID, describeErr(err)))
		return
	}

	var (
		saved  *store.User
		stored store.Credential
	)
	err = s.store.Update(func(d *store.Data) error {
		u, i := d.FindCredential(cred.ID)
		if u == nil {
			return errors.New("credential was deleted during login")
		}
		c := &u.Credentials[i]
		c.Authenticator.SignCount = cred.Authenticator.SignCount
		c.Authenticator.CloneWarning = cred.Authenticator.CloneWarning
		c.Flags = cred.Flags
		c.LastUsedAt = time.Now().UTC()
		c.UseCount++
		saved, stored = u, *c
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.withSession(sess, func() { sess.UserID = saved.ID })
	log.Printf("user %q signed in with credential %s", saved.Name, store.EncodeID(cred.ID))
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       userView(saved),
		"credential": credentialView(stored),
	})
}

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	s.modifyOwnCredential(w, r, func(u *store.User, id []byte) error {
		if !u.DeleteCredential(id) {
			return store.ErrNotFound
		}
		return nil
	})
}

func (s *Server) handleRenameCredential(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Nickname string `json:"nickname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.modifyOwnCredential(w, r, func(u *store.User, id []byte) error {
		for i := range u.Credentials {
			if string(u.Credentials[i].ID) == string(id) {
				u.Credentials[i].Nickname = truncate(strings.TrimSpace(body.Nickname), maxNickname)
				return nil
			}
		}
		return store.ErrNotFound
	})
}

func (s *Server) modifyOwnCredential(w http.ResponseWriter, r *http.Request, fn func(u *store.User, id []byte) error) {
	sess := s.getSession(w, r)
	current, err := s.currentUser(sess)
	if err != nil || current == nil {
		writeError(w, http.StatusUnauthorized, errors.New("not signed in"))
		return
	}
	id, err := store.DecodeID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bad credential id: %w", err))
		return
	}
	var saved *store.User
	err = s.store.Update(func(d *store.Data) error {
		u := d.UserByID(current.ID)
		if u == nil {
			return store.ErrNotFound
		}
		saved = u
		return fn(u, id)
	})
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, errors.New("credential not found"))
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": userView(saved)})
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	sess := s.getSession(w, r)
	current, err := s.currentUser(sess)
	if err != nil || current == nil {
		writeError(w, http.StatusUnauthorized, errors.New("not signed in"))
		return
	}
	err = s.store.Update(func(d *store.Data) error {
		d.DeleteUser(current.Name)
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.withSession(sess, func() { sess.UserID = nil })
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------- views ----------

func userView(u *store.User) map[string]any {
	creds := make([]map[string]any, len(u.Credentials))
	for i, c := range u.Credentials {
		creds[i] = credentialView(c)
	}
	return map[string]any{
		"id":          store.EncodeID(u.ID),
		"name":        u.Name,
		"displayName": u.DisplayName,
		"createdAt":   u.CreatedAt,
		"credentials": creds,
	}
}

func credentialView(c store.Credential) map[string]any {
	provider := aaguid.Lookup(c.Authenticator.AAGUID)
	v := map[string]any{
		"id":                store.EncodeID(c.ID),
		"nickname":          c.Nickname,
		"aaguid":            aaguid.Format(c.Authenticator.AAGUID),
		"aaguidName":        provider.Name,
		"iconLight":         provider.IconLight,
		"iconDark":          provider.IconDark,
		"attachment":        c.Authenticator.Attachment,
		"transports":        c.Transport,
		"attestationType":   c.AttestationType,
		"attestationFormat": c.AttestationFormat,
		"signCount":         c.Authenticator.SignCount,
		"cloneWarning":      c.Authenticator.CloneWarning,
		"flags":             c.Flags,
		"createdAt":         c.CreatedAt,
		"useCount":          c.UseCount,
		"attestation":       attestation.Summarize(c.Attestation.Object),
	}
	if !c.LastUsedAt.IsZero() {
		v["lastUsedAt"] = c.LastUsedAt
	}
	return v
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	if rec, ok := w.(*statusRecorder); ok {
		rec.note = err.Error()
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// describeErr includes the library's detailed DevInfo, which is useful in a test tool.
func describeErr(err error) error {
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.DevInfo != "" {
		return fmt.Errorf("%s: %s", pe.Details, pe.DevInfo)
	}
	return err
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func randomString(n int) string { return store.EncodeID(randomBytes(n)) }

type statusRecorder struct {
	http.ResponseWriter
	status int
	note   string // error message, logged with the request
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		msg := fmt.Sprintf("%s %s %d %s", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
		if rec.note != "" {
			msg += ": " + rec.note
		}
		log.Print(msg)
	})
}

// Config configures the server.
type Config struct {
	Addr    string
	RPID    string
	RPName  string
	Origins []string
	Data    string
	TLSCert string
	TLSKey  string
	AAGUIDs string

	// Limits for a publicly reachable server; zero means unlimited.
	MaxUsers    int
	MaxPasskeys int
	RateLimit   int  // state-changing API requests per minute per client
	TrustProxy  bool // take the client address from X-Forwarded-For
	Notice      string
}
