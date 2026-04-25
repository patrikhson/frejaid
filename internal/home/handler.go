// Package home provides the authenticated home page.
//
// In a real application this is where your app's own content lives.
// FrejaID's own UI (account settings, passkey management, admin panel) is
// deliberately kept under /settings/* and /admin/* — this page just confirms
// that the user is authenticated and shows the identity FrejaID resolved.
package home

import (
	"database/sql"
	"fmt"
	"html"
	"net/http"

	"github.com/paftech/frejaid/internal/layout"
	"github.com/paftech/frejaid/internal/middleware"
)

type Handler struct {
	db *sql.DB
}

func NewHandler(db *sql.DB) *Handler {
	return &Handler{db: db}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, requireAuth func(http.Handler) http.Handler) {
	mux.Handle("GET /", requireAuth(http.HandlerFunc(h.home)))
}

// home is the landing page for authenticated users.
// Replace the body of this handler with your own application content.
func (h *Handler) home(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	role := middleware.GetUserRole(r)
	ctx := r.Context()

	var email, displayName string
	h.db.QueryRowContext(ctx,
		`SELECT username, COALESCE(display_name, username) FROM users WHERE id = ?`, userID,
	).Scan(&email, &displayName)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, layout.PageStart("Home", role, middleware.GetCSRFToken(r)))

	fmt.Fprintf(w, `<h2>Hello, %s</h2>`, html.EscapeString(displayName))
	fmt.Fprintf(w, `<p>Authenticated as <strong>%s</strong> &middot; role: <strong>%s</strong></p>`, html.EscapeString(email), html.EscapeString(role))
	fmt.Fprint(w, `<p style="color:var(--color-text-muted)">This is a placeholder. Replace this page with your own application content.</p>`)

	if role == "admin" {
		fmt.Fprint(w, `<p><a href="/admin">Admin panel</a></p>`)
	}

	fmt.Fprint(w, layout.PageEnd())
}
