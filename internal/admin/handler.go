// Package admin provides the admin panel HTTP handlers.
//
// All routes in this package require the "admin" role, enforced by the
// RequireRole middleware wired in main.go.
//
// Admin capabilities:
//   - Review and approve/reject new registration requests
//   - List and manage all users (ban, unban, change role)
//   - Review and approve/reject credential reset requests
package admin

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"html"

	"github.com/paftech/frejaid/internal/auth"
	"github.com/paftech/frejaid/internal/hooks"
	"github.com/paftech/frejaid/internal/layout"
	"github.com/paftech/frejaid/internal/mail"
	"github.com/paftech/frejaid/internal/middleware"
)

// Handler holds shared dependencies for admin HTTP handlers.
type Handler struct {
	db      *sql.DB
	mailer  *mail.Mailer
	hooks   *hooks.Hooks
	baseURL string // used when constructing links sent in approval emails
}

// NewHandler creates an admin Handler.
func NewHandler(db *sql.DB, mailer *mail.Mailer, h *hooks.Hooks, baseURL string) *Handler {
	return &Handler{db: db, mailer: mailer, hooks: h, baseURL: baseURL}
}

// RegisterRoutes wires all admin routes into mux.
// requireAdmin is the RequireRole("admin") middleware from auth.RequireRole().
func (h *Handler) RegisterRoutes(mux *http.ServeMux, requireAdmin func(http.Handler) http.Handler) {
	mux.Handle("GET /admin", requireAdmin(http.HandlerFunc(h.dashboard)))

	// Registration management
	mux.Handle("GET /admin/registrations", requireAdmin(http.HandlerFunc(h.listRegistrations)))
	mux.Handle("POST /admin/registrations/{id}/approve", requireAdmin(http.HandlerFunc(h.approveRegistration)))
	mux.Handle("POST /admin/registrations/{id}/reject", requireAdmin(http.HandlerFunc(h.rejectRegistration)))

	// User management
	mux.Handle("GET /admin/users", requireAdmin(http.HandlerFunc(h.listUsers)))
	mux.Handle("POST /admin/users/{id}/ban", requireAdmin(http.HandlerFunc(h.banUser)))
	mux.Handle("POST /admin/users/{id}/unban", requireAdmin(http.HandlerFunc(h.unbanUser)))
	mux.Handle("POST /admin/users/{id}/role", requireAdmin(http.HandlerFunc(h.setRole)))

	// Credential reset management
	mux.Handle("GET /admin/credential-resets", requireAdmin(http.HandlerFunc(h.listCredentialResets)))
	mux.Handle("POST /admin/credential-resets/{id}/approve", requireAdmin(http.HandlerFunc(h.approveCredentialReset)))
	mux.Handle("POST /admin/credential-resets/{id}/reject", requireAdmin(http.HandlerFunc(h.rejectCredentialReset)))
}

// ─── Dashboard ───────────────────────────────────────────────────────────────

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	c := GetCounts(r.Context(), h.db)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, layout.AdminPageStart("Admin Dashboard", middleware.GetCSRFToken(r)))
	fmt.Fprintf(w, `<ul>
  <li><a href="/admin/registrations">Registrations</a> — %d pending</li>
  <li><a href="/admin/credential-resets">Credential resets</a> — %d pending</li>
  <li><a href="/admin/users">Users</a></li>
</ul>`, c.PendingRegistrations, c.PendingCredentialResets)
	fmt.Fprint(w, layout.AdminPageEnd())
}

// ─── Registration management ─────────────────────────────────────────────────

// listRegistrations shows all registration requests that are waiting for
// admin approval.  A request is ready for review when:
//   - email_verified = 1 (the user clicked the verification link)
//   - credential_data IS NOT NULL (passkey path: credential registered), OR
//   - provider = 'freja' AND credential_submitted_at IS NOT NULL (Freja path)
func (h *Handler) listRegistrations(w http.ResponseWriter, r *http.Request) {
	reqs, err := ListPendingRegistrations(r.Context(), h.db)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, layout.AdminPageStart("Pending Registrations", middleware.GetCSRFToken(r)))
	fmt.Fprint(w, `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Email</th><th>Method</th><th>Requested</th><th></th></tr></thead><tbody>`)
	for _, rq := range reqs {
		providerLabel := "Passkey"
		if rq.Provider == "freja" {
			providerLabel = "Freja eID"
		}
		fmt.Fprintf(w, `<tr>
  <td>%s</td><td>%s</td><td>%s</td><td>%s</td>
  <td>
    <form method="POST" action="/admin/registrations/%s/approve" style="display:inline">
      <button>Approve</button>
    </form>
    <form method="POST" action="/admin/registrations/%s/reject" style="display:inline">
      <button>Reject</button>
    </form>
  </td>
</tr>`, html.EscapeString(rq.Name), html.EscapeString(rq.Email), providerLabel, rq.CreatedAt.Format("2 Jan 2006"), rq.ID, rq.ID)
	}
	if len(reqs) == 0 {
		fmt.Fprint(w, `<tr><td colspan="5">No pending registrations.</td></tr>`)
	}
	fmt.Fprint(w, `</tbody></table></div>`)
	fmt.Fprint(w, layout.AdminPageEnd())
}

// approveRegistration creates the user account and sends the approval email.
// The actual work happens in auth.SendApprovalEmail, which handles both
// passkey and Freja eID registrations.
func (h *Handler) approveRegistration(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(w, r) {
		return
	}
	id := r.PathValue("id")
	if _, err := auth.SendApprovalEmail(r.Context(), h.db, h.mailer, h.hooks, h.baseURL, id); err != nil {
		http.Error(w, "Could not approve: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/registrations", http.StatusSeeOther)
}

func (h *Handler) rejectRegistration(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := RejectRegistration(r.Context(), h.db, id); err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/registrations", http.StatusSeeOther)
}

// ─── User management ─────────────────────────────────────────────────────────

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := ListUsers(r.Context(), h.db)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, layout.AdminPageStart("Users", middleware.GetCSRFToken(r)))
	fmt.Fprint(w, `<div class="table-wrap"><table><thead><tr><th>Email</th><th>Display name</th><th>Role</th><th>Banned</th><th>Joined</th><th></th></tr></thead><tbody>`)
	for _, u := range users {
		banned := "No"
		if u.IsBanned {
			banned = "Yes"
		}
		banAction := fmt.Sprintf(`<form method="POST" action="/admin/users/%s/ban" style="display:inline"><button>Ban</button></form>`, u.ID)
		if u.IsBanned {
			banAction = fmt.Sprintf(`<form method="POST" action="/admin/users/%s/unban" style="display:inline"><button>Unban</button></form>`, u.ID)
		}
		fmt.Fprintf(w, `<tr>
  <td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>
  <td>
    %s
    <form method="POST" action="/admin/users/%s/role" style="display:inline">
      <select name="role">
        <option value="passive">passive</option>
        <option value="active">active</option>
        <option value="admin">admin</option>
      </select>
      <button>Set role</button>
    </form>
  </td>
</tr>`,
			html.EscapeString(u.Username), html.EscapeString(u.DisplayName), u.Role, banned, u.CreatedAt.Format("2 Jan 2006"),
			banAction, u.ID,
		)
	}
	fmt.Fprint(w, `</tbody></table></div>`)
	fmt.Fprint(w, layout.AdminPageEnd())
}

func (h *Handler) banUser(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(w, r) {
		return
	}
	id := r.PathValue("id")
	SetUserBan(r.Context(), h.db, id, true)
	h.hooks.CallOnUserBanned(r.Context(), id)
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (h *Handler) unbanUser(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(w, r) {
		return
	}
	id := r.PathValue("id")
	SetUserBan(r.Context(), h.db, id, false)
	h.hooks.CallOnUserUnbanned(r.Context(), id)
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// setRole validates the new role value before applying it, preventing
// arbitrary values from reaching the database.
func (h *Handler) setRole(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(w, r) {
		return
	}
	role := r.FormValue("role")
	if role != "passive" && role != "active" && role != "admin" {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")
	SetUserRole(r.Context(), h.db, id, role)
	h.hooks.CallOnRoleChanged(r.Context(), id, role)
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// ─── Credential reset management ─────────────────────────────────────────────

func (h *Handler) listCredentialResets(w http.ResponseWriter, r *http.Request) {
	reqs, err := ListPendingCredentialResets(r.Context(), h.db)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, layout.AdminPageStart("Pending Credential Resets", middleware.GetCSRFToken(r)))
	fmt.Fprint(w, `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Email</th><th>Method</th><th>Requested</th><th></th></tr></thead><tbody>`)
	for _, rq := range reqs {
		providerLabel := "Passkey"
		if rq.Provider == "freja" {
			providerLabel = "Freja eID"
		}
		fmt.Fprintf(w, `<tr>
  <td>%s</td><td>%s</td><td>%s</td><td>%s</td>
  <td>
    <form method="POST" action="/admin/credential-resets/%s/approve" style="display:inline">
      <button>Approve</button>
    </form>
    <form method="POST" action="/admin/credential-resets/%s/reject" style="display:inline">
      <button>Reject</button>
    </form>
  </td>
</tr>`, html.EscapeString(rq.UserName), html.EscapeString(rq.UserEmail), providerLabel, rq.CreatedAt.Format("2 Jan 2006"), rq.ID, rq.ID)
	}
	if len(reqs) == 0 {
		fmt.Fprint(w, `<tr><td colspan="5">No pending credential resets.</td></tr>`)
	}
	fmt.Fprint(w, `</tbody></table></div>`)
	fmt.Fprint(w, layout.AdminPageEnd())
}

// approveCredentialReset generates a one-time token and sends it to the user.
// The token is valid for 48 hours and links to either the passkey reset flow
// or the Freja reset flow (which is Apache-protected).
func (h *Handler) approveCredentialReset(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(w, r) {
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()

	// Fetch the request to determine which provider and which user.
	var userID, provider string
	err := h.db.QueryRowContext(ctx,
		`SELECT user_id, provider FROM credential_reset_requests WHERE id=? AND status='pending'`,
		id,
	).Scan(&userID, &provider)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	var name, email string
	h.db.QueryRowContext(ctx,
		`SELECT COALESCE(display_name, username), username FROM users WHERE id=?`, userID,
	).Scan(&name, &email)

	// Generate a 32-character hex token (16 random bytes).
	b := make([]byte, 16)
	rand.Read(b)
	token := hex.EncodeToString(b)
	expiresAt := time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02 15:04:05")

	if err := ApproveCredentialReset(ctx, h.db, id, token, expiresAt); err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Send the appropriate setup link based on the provider.
	if provider == "freja" {
		link := h.baseURL + "/auth/reset-freja?token=" + token
		h.mailer.SendFrejaResetLink(email, name, link)
	} else {
		link := h.baseURL + "/auth/reset-passkey?token=" + token
		h.mailer.SendPasskeyResetLink(email, name, link)
	}

	http.Redirect(w, r, "/admin/credential-resets", http.StatusSeeOther)
}

func (h *Handler) rejectCredentialReset(w http.ResponseWriter, r *http.Request) {
	if !auth.ValidateCSRF(w, r) {
		return
	}
	RejectCredentialReset(r.Context(), h.db, r.PathValue("id"))
	http.Redirect(w, r, "/admin/credential-resets", http.StatusSeeOther)
}
