package middleware

// IP-based rate limiter for unauthenticated endpoints that send emails or
// touch the database in ways that are cheap to trigger and expensive to absorb
// at volume (registration, login probing, credential reset requests).
//
// Design: sliding window per client IP.  Each IP may make at most maxPerHour
// requests within the most recent 60-minute window.  Timestamps outside that
// window are discarded on each check so memory does not grow unboundedly.
//
// Placement: Apache sits in front and forwards the real client IP in
// X-Forwarded-For.  clientIP() reads the leftmost (original-client) value
// from that header, falling back to RemoteAddr when the header is absent
// (e.g. in local development without a proxy).
//
// Thread safety: a single mutex guards the entries map.  For a demo with
// modest traffic this is fine; a production service under heavy load would
// want a sharded map or an external store (Redis, Memcached).

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

type ipRateLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	max     int
	entries map[string][]time.Time
}

// NewIPRateLimiter returns middleware that allows at most maxPerHour requests
// per unique client IP within a sliding one-hour window.  Excess requests
// receive 429 Too Many Requests.
func NewIPRateLimiter(maxPerHour int) func(http.Handler) http.Handler {
	l := &ipRateLimiter{
		window:  time.Hour,
		max:     maxPerHour,
		entries: make(map[string][]time.Time),
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !l.allow(clientIP(r)) {
				http.Error(w, "Too many requests. Please try again later.", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// allow returns true and records the current timestamp if the IP is within
// quota, or false (without recording) if the quota is already exhausted.
func (l *ipRateLimiter) allow(ip string) bool {
	now := time.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	// Compact: keep only timestamps inside the current window.
	ts := l.entries[ip]
	j := 0
	for _, t := range ts {
		if t.After(cutoff) {
			ts[j] = t
			j++
		}
	}
	ts = ts[:j]

	if len(ts) >= l.max {
		l.entries[ip] = ts
		return false
	}
	l.entries[ip] = append(ts, now)
	return true
}

// clientIP extracts the real client IP address.  The app runs behind Apache
// which sets X-Forwarded-For; the leftmost value is the original client.
// Without a proxy (local dev) we fall back to RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
	}
	// RemoteAddr is "host:port"; strip the port.
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}
