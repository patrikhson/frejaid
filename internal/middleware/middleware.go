package middleware

import (
	"context"
	"log"
	"net/http"
	"time"
)

type contextKey string

const UserIDKey contextKey = "userID"
const UserRoleKey contextKey = "userRole"

// Logging logs each request.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

// SecurityHeaders adds basic security headers to every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// WithValue stores a value in the request context.
func WithValue(r *http.Request, key contextKey, value string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), key, value))
}

// GetUserID retrieves the user ID from the request context.
func GetUserID(r *http.Request) string {
	v, _ := r.Context().Value(UserIDKey).(string)
	return v
}

// GetUserRole retrieves the user role from the request context.
func GetUserRole(r *http.Request) string {
	v, _ := r.Context().Value(UserRoleKey).(string)
	return v
}
