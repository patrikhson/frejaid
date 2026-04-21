package admin

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/paftech/frejaid/internal/auth"
	"github.com/paftech/frejaid/internal/layout"
	"github.com/paftech/frejaid/internal/mail"
)

type Handler struct {
	db      *sql.DB
	mailer  *mail.Mailer
	baseURL string
}

func NewHandler(db *sql.DB, mailer *mail.Mailer, baseURL string) *Handler {
	return &Handler{db: db, mailer: mailer, baseURL: baseURL}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, requireAdmin func(http.Handler) http.Handler) {
	mux.Handle("GET /admin", requireAdmin(http.HandlerFunc(h.dashboard)))
	mux.Handle("GET /admin/registrations", requireAdmin(http.HandlerFunc(h.listRegistrations)))
	mux.Handle("POST /admin/registrations/{id}/approve", requireAdmin(http.HandlerFunc(h.approveRegistration)))
	mux.Handle("POST /admin/registrations/{id}/reject", requireAdmin(http.HandlerFunc(h.rejectRegistration)))
	mux.Handle("GET /admin/users", requireAdmin(http.HandlerFunc(h.listUsers)))
	mux.Handle("POST /admin/users/{id}/ban", requireAdmin(http.HandlerFunc(h.banUser)))
	mux.Handle("POST /admin/users/{id}/unban", requireAdmin(http.HandlerFunc(h.unbanUser)))
	mux.Handle("POST /admin/users/{id}/role", requireAdmin(http.HandlerFunc(h.setRole)))
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	c := GetCounts(r.Context(), h.db)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, layout.AdminPageStart("Admin Dashboard"))
	fmt.Fprintf(w, `<ul>
  <li><a href="/admin/registrations">Registrations</a> — %d pending</li>
  <li><a href="/admin/users">Users</a></li>
</ul>`, c.PendingRegistrations)
	fmt.Fprint(w, layout.AdminPageEnd())
}

func (h *Handler) listRegistrations(w http.ResponseWriter, r *http.Request) {
	reqs, err := ListPendingRegistrations(r.Context(), h.db)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, layout.AdminPageStart("Pending Registrations"))
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
</tr>`, rq.Name, rq.Email, providerLabel, rq.CreatedAt.Format("2 Jan 2006"), rq.ID, rq.ID)
	}
	if len(reqs) == 0 {
		fmt.Fprint(w, `<tr><td colspan="5">No pending registrations.</td></tr>`)
	}
	fmt.Fprint(w, `</tbody></table></div>`)
	fmt.Fprint(w, layout.AdminPageEnd())
}

func (h *Handler) approveRegistration(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := auth.SendApprovalEmail(r.Context(), h.db, h.mailer, h.baseURL, id); err != nil {
		http.Error(w, "Could not approve: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/registrations", http.StatusSeeOther)
}

func (h *Handler) rejectRegistration(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := RejectRegistration(r.Context(), h.db, id); err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/registrations", http.StatusSeeOther)
}

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := ListUsers(r.Context(), h.db)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, layout.AdminPageStart("Users"))
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
			u.Username, u.DisplayName, u.Role, banned, u.CreatedAt.Format("2 Jan 2006"),
			banAction, u.ID,
		)
	}
	fmt.Fprint(w, `</tbody></table></div>`)
	fmt.Fprint(w, layout.AdminPageEnd())
}

func (h *Handler) banUser(w http.ResponseWriter, r *http.Request) {
	SetUserBan(r.Context(), h.db, r.PathValue("id"), true)
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (h *Handler) unbanUser(w http.ResponseWriter, r *http.Request) {
	SetUserBan(r.Context(), h.db, r.PathValue("id"), false)
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (h *Handler) setRole(w http.ResponseWriter, r *http.Request) {
	role := r.FormValue("role")
	if role != "passive" && role != "active" && role != "admin" {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}
	SetUserRole(r.Context(), h.db, r.PathValue("id"), role)
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}
