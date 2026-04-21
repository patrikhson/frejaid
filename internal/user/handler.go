package user

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/paftech/frejaid/internal/layout"
	"github.com/paftech/frejaid/internal/mail"
	"github.com/paftech/frejaid/internal/middleware"
)

type Handler struct {
	db      *sql.DB
	mailer  *mail.Mailer
	baseURL string
	isProd  bool
}

func NewHandler(db *sql.DB, mailer *mail.Mailer, baseURL string, isProd bool) *Handler {
	return &Handler{db: db, mailer: mailer, baseURL: baseURL, isProd: isProd}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, requireAuth func(http.Handler) http.Handler) {
	mux.Handle("GET /settings/profile", requireAuth(http.HandlerFunc(h.editProfile)))
	mux.Handle("POST /settings/profile", requireAuth(http.HandlerFunc(h.saveProfile)))
	mux.Handle("GET /settings/account", requireAuth(http.HandlerFunc(h.showAccount)))
	mux.Handle("POST /settings/email", requireAuth(http.HandlerFunc(h.requestEmailChange)))
	mux.HandleFunc("GET /auth/verify-email-change", h.confirmEmailChange)
}

func (h *Handler) editProfile(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	role := middleware.GetUserRole(r)

	var displayName string
	h.db.QueryRowContext(r.Context(),
		`SELECT COALESCE(display_name,'') FROM users WHERE id=?`, userID,
	).Scan(&displayName)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, layout.PageStart("Edit Profile", role, ""))
	fmt.Fprintf(w, `<h2>Edit Profile</h2>
<form class="form" method="POST" action="/settings/profile">
  <label>Display name
    <input type="text" name="display_name" value="%s" maxlength="80">
  </label>
  <div style="display:flex;gap:10px;align-items:center;margin-top:1rem">
    <button type="submit" class="btn">Save</button>
    <a href="/settings/account">Cancel</a>
  </div>
</form>`, displayName)
	fmt.Fprint(w, layout.PageEnd())
}

func (h *Handler) saveProfile(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	displayName := strings.TrimSpace(r.FormValue("display_name"))
	if len(displayName) > 80 {
		displayName = displayName[:80]
	}

	var dnVal interface{} = displayName
	if displayName == "" {
		dnVal = nil
	}

	_, err := h.db.ExecContext(r.Context(),
		`UPDATE users SET display_name=?, updated_at=datetime('now') WHERE id=?`,
		dnVal, userID,
	)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/settings/account", http.StatusSeeOther)
}

func (h *Handler) showAccount(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	role := middleware.GetUserRole(r)
	ctx := r.Context()

	var email, displayName string
	h.db.QueryRowContext(ctx,
		`SELECT username, COALESCE(display_name, username) FROM users WHERE id=?`, userID,
	).Scan(&email, &displayName)

	var passkeyCount int
	h.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=?`, userID,
	).Scan(&passkeyCount)

	var frejaEmail string
	h.db.QueryRowContext(ctx,
		`SELECT COALESCE(provider_email,'') FROM user_identities
		 WHERE user_id=? AND provider='freja' LIMIT 1`,
		userID,
	).Scan(&frejaEmail)

	flash := r.URL.Query().Get("linked")
	if flash == "" {
		flash = r.URL.Query().Get("unlinked")
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, layout.PageStart("Account Settings", role, ""))
	fmt.Fprint(w, `<h2>Account Settings</h2>`)

	if flash == "freja" {
		fmt.Fprint(w, `<div class="alert alert-success">Freja eID updated successfully.</div>`)
	}

	fmt.Fprint(w, `<section><h3>Login methods</h3><table>`)
	fmt.Fprintf(w, `<tr><td>Passkey</td><td>%d registered</td><td><a href="/settings/passkeys">Manage</a></td></tr>`, passkeyCount)

	if frejaEmail != "" {
		frejaUnlinkBtn := ""
		if passkeyCount > 0 {
			frejaUnlinkBtn = `<form method="POST" action="/settings/freja/unlink" style="display:inline">
				<button type="submit" onclick="return confirm('Unlink Freja eID?')">Unlink</button>
			</form>`
		}
		fmt.Fprintf(w, `<tr><td>Freja eID</td><td>%s</td><td>%s</td></tr>`, frejaEmail, frejaUnlinkBtn)
	} else {
		fmt.Fprint(w, `<tr><td>Freja eID</td><td>Not linked</td><td><a href="/auth/freja/link">Link Freja eID</a></td></tr>`)
	}
	fmt.Fprint(w, `</table></section>`)

	fmt.Fprintf(w, `<section><h3>Display name</h3>
<p>Current: <strong>%s</strong></p>
<p><a href="/settings/profile">Edit display name</a></p>
</section>`, displayName)

	fmt.Fprintf(w, `<section><h3>Email address</h3>
<p>Current: <strong>%s</strong></p>
<form class="form" method="POST" action="/settings/email">
  <label>New email address
    <input type="email" name="new_email" required>
  </label>
  <p><small>A verification link will be sent to your new address.</small></p>
  <button type="submit" class="btn">Change email</button>
</form>
</section>`, email)

	fmt.Fprint(w, layout.PageEnd())
}

func (h *Handler) requestEmailChange(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	ctx := r.Context()

	newEmail := strings.TrimSpace(strings.ToLower(r.FormValue("new_email")))
	if newEmail == "" {
		http.Error(w, "Email required", http.StatusBadRequest)
		return
	}

	var taken bool
	h.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(username)=? AND id!=?)`,
		newEmail, userID,
	).Scan(&taken)
	if taken {
		http.Error(w, "That email address is already in use.", http.StatusConflict)
		return
	}

	var name string
	h.db.QueryRowContext(ctx,
		`SELECT COALESCE(display_name, username) FROM users WHERE id=?`, userID,
	).Scan(&name)

	b := make([]byte, 16)
	rand.Read(b)
	token := hex.EncodeToString(b)
	expiresAt := time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02 15:04:05")

	_, err := h.db.ExecContext(ctx,
		`INSERT INTO email_change_tokens (token, user_id, new_email, expires_at) VALUES (?, ?, ?, ?)`,
		token, userID, newEmail, expiresAt,
	)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	link := h.baseURL + "/auth/verify-email-change?token=" + token
	if err := h.mailer.SendEmailChange(newEmail, name, link); err != nil {
		fmt.Printf("email change mail error: %v\n", err)
	}

	role := middleware.GetUserRole(r)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, layout.PageStart("Email change requested", role, ""))
	fmt.Fprintf(w, `<h2>Check your email</h2>
<p>A verification link has been sent to <strong>%s</strong>.</p>
<p>Click the link in that email to confirm the change. It expires in 24 hours.</p>
<p><a href="/settings/account">Back to account settings</a></p>`, newEmail)
	fmt.Fprint(w, layout.PageEnd())
}

func (h *Handler) confirmEmailChange(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Invalid link", http.StatusBadRequest)
		return
	}
	ctx := r.Context()

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	var userID, newEmail string
	err := h.db.QueryRowContext(ctx,
		`DELETE FROM email_change_tokens WHERE token=? AND expires_at > ? RETURNING user_id, new_email`,
		token, now,
	).Scan(&userID, &newEmail)
	if err != nil {
		http.Error(w, "Link expired or invalid.", http.StatusBadRequest)
		return
	}

	_, err = h.db.ExecContext(ctx,
		`UPDATE users SET username=?, updated_at=datetime('now') WHERE id=?`, newEmail, userID,
	)
	if err != nil {
		http.Error(w, "Server error — email may already be in use.", http.StatusConflict)
		return
	}
	h.db.ExecContext(ctx,
		`UPDATE user_identities SET provider_email=? WHERE user_id=? AND provider='freja'`,
		newEmail, userID,
	)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Email updated — FrejaID Demo</title>
<link rel="stylesheet" href="/static/css/site.css"></head>
<body>
<header class="site-header"><div class="site-header__inner"><a href="/" class="site-logo">FrejaID Demo</a></div></header>
<main class="site-main">
  <h2>Email address updated</h2>
  <p>Your email has been changed to <strong>%s</strong>.</p>
  <p><a href="/settings/account">Back to account settings</a></p>
</main>
<footer class="site-footer"><p>FrejaID Demo</p></footer>
</body></html>`, newEmail)
}
