// Package middleware provides HTTP middleware and request-context helpers.
package middleware

import (
	"context"
	"log"
	"net/http"
	"time"
)

// contextKey is an unexported type for context keys in this package.
// Using a named type prevents collisions with keys from other packages.
type contextKey string

// UserIDKey and UserRoleKey are the context keys where the session middleware
// stores the authenticated user's ID and role.  Handlers retrieve these with
// GetUserID / GetUserRole rather than using the keys directly.
const UserIDKey contextKey = "userID"
const UserRoleKey contextKey = "userRole"

// Logging logs each request's method, path, and elapsed time.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

// SecurityHeaders adds basic HTTP security headers to every response.
//
//   X-Frame-Options: DENY
//     Prevents the page from being embedded in an <iframe>, mitigating
//     clickjacking attacks.
//
//   X-Content-Type-Options: nosniff
//     Tells browsers not to guess the Content-Type from the response body,
//     preventing MIME-type confusion attacks.
//
//   Referrer-Policy: strict-origin-when-cross-origin
//     Sends the full referrer for same-origin requests, only the origin for
//     cross-origin requests, and nothing for downgrade (HTTPS → HTTP).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// WithValue returns a shallow copy of r with the given key-value pair stored
// in the request context.  Used by session middleware to propagate user info.
func WithValue(r *http.Request, key contextKey, value string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), key, value))
}

// GetUserID retrieves the authenticated user's ID from the request context.
// Returns an empty string if no user is authenticated (should not happen
// inside a requireAuth-protected handler).
func GetUserID(r *http.Request) string {
	v, _ := r.Context().Value(UserIDKey).(string)
	return v
}

// GetUserRole retrieves the authenticated user's role from the request context.
// Returns an empty string if no user is authenticated.
func GetUserRole(r *http.Request) string {
	v, _ := r.Context().Value(UserRoleKey).(string)
	return v
}
