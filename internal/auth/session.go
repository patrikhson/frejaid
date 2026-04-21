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

const sessionCookie = "session"
const sessionDuration = 30 * 24 * time.Hour

type Session struct {
	ID       string
	UserID   string
	UserRole string
}

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
	// Update last_seen_at in the background — ignore errors
	db.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = datetime('now') WHERE id = ?`, s.ID)
	return &s, nil
}

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
func RequireAuth(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s, _ := GetSession(r.Context(), db, r)
			if s == nil {
				http.Redirect(w, r, "/auth/login", http.StatusFound)
				return
			}
			r = middleware.WithValue(r, middleware.UserIDKey, s.UserID)
			r = middleware.WithValue(r, middleware.UserRoleKey, s.UserRole)
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole middleware — returns 403 if role doesn't match.
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

// CleanupSessions deletes expired sessions. Run periodically.
func CleanupSessions(ctx context.Context, db *sql.DB) {
	db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < datetime('now')`)
}
