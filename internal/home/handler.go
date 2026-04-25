// Package home provides the authenticated home page / dashboard handler.
package home

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/paftech/frejaid/internal/layout"
	"github.com/paftech/frejaid/internal/middleware"
)

// Handler holds the database connection for home page queries.
type Handler struct {
	db *sql.DB
}

func NewHandler(db *sql.DB) *Handler {
	return &Handler{db: db}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, requireAuth func(http.Handler) http.Handler) {
	mux.Handle("GET /", requireAuth(http.HandlerFunc(h.dashboard)))
}

// dashboard is the landing page for authenticated users.
// It shows the user's current login methods and, for admins, a link to the
// admin panel with the count of pending registrations.
func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	role := middleware.GetUserRole(r)
	ctx := r.Context()

	var email, displayName string
	h.db.QueryRowContext(ctx,
		`SELECT username, COALESCE(display_name, username) FROM users WHERE id = ?`, userID,
	).Scan(&email, &displayName)

	var passkeyCount int
	h.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`, userID,
	).Scan(&passkeyCount)

	var frejaEmail string
	h.db.QueryRowContext(ctx,
		`SELECT COALESCE(provider_email,'') FROM user_identities
		 WHERE user_id = ? AND provider = 'freja' LIMIT 1`,
		userID,
	).Scan(&frejaEmail)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, layout.PageStart("Dashboard", role, ""))

	fmt.Fprintf(w, `<h2>Welcome, %s</h2>`, displayName)
	fmt.Fprintf(w, `<p>Logged in as: <strong>%s</strong></p>`, email)
	fmt.Fprintf(w, `<p>Role: <strong>%s</strong></p>`, role)

	// Login methods summary — links to the relevant settings pages.
	fmt.Fprint(w, `<hr><h3>Login methods</h3><table>`)
	fmt.Fprintf(w, `<tr><td>Passkey</td><td>%d registered</td><td><a href="/settings/passkeys">Manage</a></td></tr>`, passkeyCount)
	if frejaEmail != "" {
		fmt.Fprintf(w, `<tr><td>Freja eID</td><td>%s</td><td><a href="/settings/account">Manage</a></td></tr>`, frejaEmail)
	} else {
		fmt.Fprint(w, `<tr><td>Freja eID</td><td>Not linked</td><td><a href="/auth/freja/link">Link Freja eID</a></td></tr>`)
	}
	fmt.Fprint(w, `</table>`)

	// Show the admin panel link only to admins, with the count of items needing
	// attention so they don't have to navigate in to see if anything is pending.
	if role == "admin" {
		var pendingCount int
		h.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM registration_requests
			 WHERE status='pending' AND email_verified=1
			   AND (credential_data IS NOT NULL OR (provider='freja' AND credential_submitted_at IS NOT NULL))`,
		).Scan(&pendingCount)
		fmt.Fprintf(w, `<hr><h3>Admin</h3><p><a href="/admin">Admin dashboard</a> — %d pending registration(s)</p>`, pendingCount)
	}

	fmt.Fprint(w, layout.PageEnd())
}
