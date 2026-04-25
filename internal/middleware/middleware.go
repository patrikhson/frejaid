// Package middleware provides HTTP middleware and request-context helpers.
package middleware

import (
	"context"
	"log"
	"net/http"
	"time"
)

type contextKey string

const (
	UserIDKey    contextKey = "userID"
	UserRoleKey  contextKey = "userRole"
	SessionIDKey contextKey = "sessionID"
	CSRFTokenKey contextKey = "csrfToken"
)

// Logging logs each request's method, path, and elapsed time.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

// SecurityHeaders adds basic HTTP security headers to every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// WithValue returns a shallow copy of r with the given key-value pair stored
// in the request context.
func WithValue(r *http.Request, key contextKey, value string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), key, value))
}

func GetUserID(r *http.Request) string {
	v, _ := r.Context().Value(UserIDKey).(string)
	return v
}

func GetUserRole(r *http.Request) string {
	v, _ := r.Context().Value(UserRoleKey).(string)
	return v
}

func GetSessionID(r *http.Request) string {
	v, _ := r.Context().Value(SessionIDKey).(string)
	return v
}

// GetCSRFToken retrieves the expected CSRF token from the request context.
// It is set by RequireAuth after a successful session lookup.
func GetCSRFToken(r *http.Request) string {
	v, _ := r.Context().Value(CSRFTokenKey).(string)
	return v
}
