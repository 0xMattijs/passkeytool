package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	l := newRateLimiter(3, false)
	now := time.Now()
	for i := range 3 {
		if !l.allow("a", now) {
			t.Fatalf("request %d refused within the burst", i+1)
		}
	}
	if l.allow("a", now) {
		t.Fatal("fourth request allowed")
	}
	if !l.allow("b", now) {
		t.Fatal("another client was limited")
	}
	if !l.allow("a", now.Add(20*time.Second)) {
		t.Fatal("a token wasn't refilled after 20 seconds at 3 per minute")
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/logout", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.7")
	if got := clientIP(r, false); got != "10.0.0.1" {
		t.Errorf("untrusted proxy: got %s, want the socket address", got)
	}
	if got := clientIP(r, true); got != "203.0.113.7" {
		t.Errorf("trusted proxy: got %s, want the last X-Forwarded-For entry", got)
	}
}

func TestPublicLimits(t *testing.T) {
	cfg := serveConfig{
		RPID: "localhost", RPName: "test", Origins: []string{"http://localhost:8080"},
		MaxUsers: 1, RateLimit: 2,
	}
	store := NewStore(filepath.Join(t.TempDir(), "data.json"))
	if err := store.Update(func(d *storeData) error {
		d.Users = append(d.Users, &User{ID: []byte("u1"), Name: "alice"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	post := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:5000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	w := post("/api/register/begin", `{"username":"bob"}`)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "full") {
		t.Errorf("register on a full server: %d %s", w.Code, w.Body)
	}
	w = post("/api/register/begin", `{"username":"`+strings.Repeat("x", maxNameLen+1)+`"}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "at most") {
		t.Errorf("overlong username: %d %s", w.Code, w.Body)
	}
	// The limit is 2 per minute, so the third request is refused.
	if w = post("/api/logout", ""); w.Code != http.StatusTooManyRequests {
		t.Errorf("third request: got %d, want 429", w.Code)
	}

	big := httptest.NewRequest("POST", "/api/register/begin", strings.NewReader(strings.Repeat(" ", maxBodyBytes+1)))
	big.RemoteAddr = "192.0.2.2:5000"
	bw := httptest.NewRecorder()
	h.ServeHTTP(bw, big)
	if bw.Code != http.StatusBadRequest {
		t.Errorf("oversized body: got %d, want 400", bw.Code)
	}
}

func TestSessionCap(t *testing.T) {
	srv, err := NewServer(serveConfig{RPID: "localhost", RPName: "test", Origins: []string{"http://localhost:8080"}},
		NewStore(filepath.Join(t.TempDir(), "data.json")))
	if err != nil {
		t.Fatal(err)
	}
	for range maxSessions + 5 {
		srv.getSession(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/me", nil))
	}
	if n := len(srv.session); n != maxSessions {
		t.Errorf("sessions: got %d, want the cap %d", n, maxSessions)
	}
}
