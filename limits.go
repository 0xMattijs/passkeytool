package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Limits that keep a publicly reachable server from being filled up by
// strangers. They're off by default, because serve normally runs on
// localhost for one developer.

const (
	maxBodyBytes = 1 << 20 // every request body
	maxSessions  = 10000   // browser sessions held in memory
	maxNickname  = 64      // passkey nickname length
	maxNameLen   = 64      // username and display name length
)

// limitBodies caps every request body, so a client can't stream an
// unbounded body into a handler.
func limitBodies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// rateLimiter is a per-client token bucket for state-changing API requests.
type rateLimiter struct {
	perMinute  int
	trustProxy bool
	mu         sync.Mutex
	buckets    map[string]*bucket
	lastSweep  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perMinute int, trustProxy bool) *rateLimiter {
	return &rateLimiter{perMinute: perMinute, trustProxy: trustProxy, buckets: map[string]*bucket{}}
}

func (l *rateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	burst := float64(l.perMinute)
	if now.Sub(l.lastSweep) > time.Minute {
		// A bucket idle for a minute is full again, so it can be dropped.
		for k, b := range l.buckets {
			if now.Sub(b.last) > time.Minute {
				delete(l.buckets, k)
			}
		}
		l.lastSweep = now
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Minutes() * burst
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *rateLimiter) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/") &&
			!l.allow(clientIP(r, l.trustProxy), time.Now()) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, errTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP returns the address that requests are limited by. Behind a
// trusted proxy such as Cloud Run, that's the last X-Forwarded-For entry,
// which the proxy appends itself; earlier entries come from the client and
// can be forged.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// truncate shortens s to at most n runes.
func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
