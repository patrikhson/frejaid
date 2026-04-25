// auth/check.go — the /auth/check endpoint used by Apache mod_auth_request.
//
// This is the integration point for Scenario 1A (wrapping an existing app).
//
// Apache calls GET /auth/check before forwarding every request to the existing
// app.  This handler reads the FrejaID session cookie and responds:
//
//   200 OK  — session is valid; response headers carry the user identity
//   401     — no session, expired, or banned; Apache redirects to /auth/login
//
// Apache then copies the X-FrejaID-* response headers from this 200 response
// onto the forwarded request, so the existing app receives them as request
// headers.  See config/apache-existing-app.conf for the full Apache setup.
//
// Security note: the existing app must only be reachable via Apache (i.e. the
// Go app listens on 127.0.0.1, not 0.0.0.0).  Apache must strip any incoming
// X-FrejaID-* headers before adding its own — the example config does this.
package auth

import (
	"net/http"
)

// checkAuth handles GET /auth/check.
// It is intentionally not behind requireAuth middleware because that middleware
// redirects to /auth/login, whereas Apache needs a plain 401 status code.
func (h *Handler) checkAuth(w http.ResponseWriter, r *http.Request) {
	s, _ := GetSession(r.Context(), h.db, r)
	if s == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Fetch the display name — not stored in the session to avoid stale data.
	var name, email string
	h.db.QueryRowContext(r.Context(),
		`SELECT COALESCE(display_name, username), username FROM users WHERE id = ?`,
		s.UserID,
	).Scan(&name, &email)

	// These headers are copied by Apache onto the forwarded request so the
	// existing app receives them as ordinary request headers.
	w.Header().Set("X-FrejaID-User-ID", s.UserID)
	w.Header().Set("X-FrejaID-User-Email", email)
	w.Header().Set("X-FrejaID-User-Role", s.UserRole)
	w.Header().Set("X-FrejaID-User-Name", name)
	w.WriteHeader(http.StatusOK)
}
