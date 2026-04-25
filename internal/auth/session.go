// Session management for FrejaID Demo.
//
// Sessions are stored server-side in the sessions table.  The browser holds
// only a session ID in an HttpOnly cookie.  This means:
//
//   • We can invalidate sessions instantly (e.g. when banning a user) without
//     waiting for the cookie to expire or issuing a new token.
//   • The session ID is never accessible to JavaScript (HttpOnly).
//   • The session ID is transmitted only over HTTPS in production (Secure).
//   • The cookie is SameSite=Lax which prevents CSRF via cross-site requests
//     while still working with top-level navigation (email links, redirects).
package auth

import (
	"context"
	"database/sql"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/paftech/frejaid/internal/middleware"
)

const (
	sessionCookie   = "session"
	sessionDuration = 30 * 24 * time.Hour // 30-day rolling sessions
)

// Session contains the fields read from the sessions + users tables on every
// authenticated request.
type Session struct {
	ID       string
	UserID   string
	UserRole string
}

// CreateSession inserts a new session row and sets the session cookie.
// Called after a successful login (passkey or Freja eID).
func CreateSession(ctx context.Context, db *sql.DB, w http.ResponseWriter, r *http.Request, userID string, secure bool) error {
	id := uuid.NewString()

	// Extract the client IP; RemoteAddr is "IP:port" for TCP connections.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr // fallback for unusual formats
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
		HttpOnly: true,              // not accessible via JavaScript
		Secure:   secure,            // HTTPS only in production
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionDuration.Seconds()),
	})
	return nil
}

// GetSession looks up the session cookie in the request, validates it against
// the database, and returns the session.  Returns nil (no error) if the cookie
// is missing or the session is invalid — callers treat nil as "not logged in".
func GetSession(ctx context.Context, db *sql.DB, r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, nil // no cookie → not logged in
	}

	var s Session
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	err = db.QueryRowContext(ctx,
		// Join with users to check the ban flag in the same query, so a newly
		// banned user is rejected on their next request without any cache.
		`SELECT s.id, s.user_id, u.role
		 FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.id = ? AND s.expires_at > ? AND u.is_banned = 0`,
		cookie.Value, now,
	).Scan(&s.ID, &s.UserID, &s.UserRole)
	if err != nil {
		return nil, nil // expired, invalid, or banned → not logged in
	}

	// Update last_seen_at so we know when the session was last active.
	// This is a best-effort write; we don't need to propagate the error.
	db.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = datetime('now') WHERE id = ?`, s.ID)

	return &s, nil
}

// DeleteSession removes the session row from the database and clears the
// session cookie.  Called on logout.
func DeleteSession(ctx context.Context, db *sql.DB, w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, cookie.Value)
	}
	// Overwrite the cookie with an expired value so the browser removes it.
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookie,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

// RequireAuth is middleware that redirects unauthenticated requests to the
// login page.  If the session is valid it stores the user ID and role in the
// request context so downstream handlers can retrieve them with
// middleware.GetUserID / middleware.GetUserRole.
func RequireAuth(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s, _ := GetSession(r.Context(), db, r)
			if s == nil {
				http.Redirect(w, r, "/auth/login", http.StatusFound)
				return
			}
			// Store user info in context so handlers don't need the database
			// just to know who is making the request.
			r = middleware.WithValue(r, middleware.UserIDKey, s.UserID)
			r = middleware.WithValue(r, middleware.UserRoleKey, s.UserRole)
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole is middleware that enforces a minimum role.  It wraps
// RequireAuth so unauthenticated users are still redirected to login.
func RequireRole(db *sql.DB, role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return RequireAuth(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if middleware.GetUserRole(r) != role {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// CleanupSessions deletes all expired sessions.  Call this periodically
// (e.g. hourly) to keep the sessions table from growing unboundedly.
func CleanupSessions(ctx context.Context, db *sql.DB) {
	db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < datetime('now')`)
}
