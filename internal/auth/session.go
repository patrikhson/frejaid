// Session management for FrejaID Demo.
//
// Sessions are stored server-side in the sessions table.  The browser holds
// only a session ID in an HttpOnly cookie.  This means:
//
//   - We can invalidate sessions instantly (e.g. when banning a user).
//   - The session ID is never accessible to JavaScript (HttpOnly).
//   - The session ID is only sent over HTTPS in production (Secure).
//   - SameSite=Lax prevents CSRF via cross-site requests while still
//     allowing top-level navigation (email links, redirects).
//
// CSRF protection
//
// Every authenticated page embeds a CSRF token derived as
// HMAC-SHA256(sessionID, SESSION_SECRET).  All state-changing POST handlers
// call ValidateCSRF to verify the token from the form or X-CSRF-Token header.
// The token is deterministic from the session, so it never needs to be stored.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/paftech/frejaid/internal/middleware"
)

const (
	sessionCookie   = "session"
	sessionDuration = 30 * 24 * time.Hour
)

// Session contains the fields read from the sessions + users tables on every
// authenticated request.
type Session struct {
	ID       string
	UserID   string
	UserRole string
}

// CSRFToken derives a CSRF token from a session ID and the application secret.
// Using HMAC means the token can be recomputed without storing it.
func CSRFToken(sessionID, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sessionID))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidateCSRF checks the CSRF token submitted with a POST request against
// the expected value stored in the request context by RequireAuth.
// Returns false and writes a 403 if the token is missing or wrong.
func ValidateCSRF(w http.ResponseWriter, r *http.Request) bool {
	expected := middleware.GetCSRFToken(r)
	if expected == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false
	}
	got := r.FormValue("csrf_token")
	if got == "" {
		got = r.Header.Get("X-CSRF-Token")
	}
	// hmac.Equal is constant-time to prevent timing attacks.
	if !hmac.Equal([]byte(got), []byte(expected)) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return false
	}
	return true
}

// CreateSession inserts a new session row and sets the session cookie.
func CreateSession(ctx context.Context, db *sql.DB, w http.ResponseWriter, r *http.Request, userID string, secure bool) error {
	id := uuid.NewString()
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	expiresAt := time.Now().UTC().Add(sessionDuration).Format("2006-01-02 15:04:05")
	_, err = db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, ip_address, user_agent, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id, userID, ip, r.UserAgent(), expiresAt,
	)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionDuration.Seconds()),
	})
	return nil
}

// GetSession looks up the session cookie and validates it against the database.
// Returns nil (no error) if the cookie is missing or the session is invalid.
func GetSession(ctx context.Context, db *sql.DB, r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, nil
	}
	var s Session
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	err = db.QueryRowContext(ctx,
		`SELECT s.id, s.user_id, u.role
		 FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.id = ? AND s.expires_at > ? AND u.is_banned = 0`,
		cookie.Value, now,
	).Scan(&s.ID, &s.UserID, &s.UserRole)
	if err != nil {
		return nil, nil
	}
	db.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = datetime('now') WHERE id = ?`, s.ID)
	return &s, nil
}

// DeleteSession removes the session from the database and clears the cookie.
func DeleteSession(ctx context.Context, db *sql.DB, w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookie,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

// RequireAuth middleware — redirects to login if no valid session.
// Also stores the session ID and a derived CSRF token in the request context
// so handlers can validate CSRF tokens without an extra database lookup.
func RequireAuth(db *sql.DB, secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s, _ := GetSession(r.Context(), db, r)
			if s == nil {
				http.Redirect(w, r, "/auth/login", http.StatusFound)
				return
			}
			r = middleware.WithValue(r, middleware.UserIDKey, s.UserID)
			r = middleware.WithValue(r, middleware.UserRoleKey, s.UserRole)
			r = middleware.WithValue(r, middleware.SessionIDKey, s.ID)
			r = middleware.WithValue(r, middleware.CSRFTokenKey, CSRFToken(s.ID, secret))
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole middleware — enforces a minimum role, wraps RequireAuth.
func RequireRole(db *sql.DB, secret, role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return RequireAuth(db, secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if middleware.GetUserRole(r) != role {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// CleanupSessions deletes expired sessions. Run periodically.
func CleanupSessions(ctx context.Context, db *sql.DB) {
	db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < datetime('now')`)
}
