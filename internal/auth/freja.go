package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/paftech/frejaid/internal/middleware"
)

func frejaEmail(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Remote-User"))
}

func frejaName(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Freja-Name"))
}

func frejaSub(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Freja-Sub"))
}

func randToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// frejaRegister — GET /auth/freja/register?token=…
func (h *Handler) frejaRegister(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	email := frejaEmail(r)
	name := frejaName(r)
	sub := frejaSub(r)

	if email == "" {
		http.Error(w, "No authenticated email received from Freja eID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	now := time.Now().UTC().Format("2006-01-02 15:04:05")

	var reqID, reqEmail, reqName string
	err := h.db.QueryRowContext(ctx,
		`SELECT id, email, name FROM registration_requests
		 WHERE passkey_token = ? AND passkey_token_expires_at > ?
		   AND status = 'pending' AND email_verified = 1`,
		token, now,
	).Scan(&reqID, &reqEmail, &reqName)
	if err != nil {
		http.Error(w, "Invalid or expired link", http.StatusBadRequest)
		return
	}

	if !strings.EqualFold(email, reqEmail) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, frejaEmailMismatchHTML, email, reqEmail)
		return
	}

	if name != "" && reqName == "" {
		h.db.ExecContext(ctx, `UPDATE registration_requests SET name = ? WHERE id = ?`, name, reqID)
	}

	_, err = h.db.ExecContext(ctx,
		`UPDATE registration_requests
		 SET provider = 'freja', freja_sub = ?, passkey_registered_at = datetime('now')
		 WHERE id = ?`,
		sub, reqID,
	)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/auth/pending", http.StatusSeeOther)
}

// frejaLogin — GET /auth/freja/login
func (h *Handler) frejaLogin(w http.ResponseWriter, r *http.Request) {
	email := frejaEmail(r)
	sub := frejaSub(r)
	name := frejaName(r)

	if email == "" {
		http.Error(w, "No authenticated email received from Freja eID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// 1. Known Freja identity — log in directly.
	var userID string
	err := h.db.QueryRowContext(ctx,
		`SELECT user_id FROM user_identities
		 WHERE provider = 'freja'
		   AND (provider_subject = ? OR LOWER(provider_email) = LOWER(?))
		 LIMIT 1`,
		sub, email,
	).Scan(&userID)
	if err == nil {
		if err2 := CreateSession(ctx, h.db, w, r, userID, h.isProd); err2 != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// 2. Existing passkey account with the same email — confirm before linking.
	var existingUserID, existingName string
	err = h.db.QueryRowContext(ctx,
		`SELECT id, COALESCE(display_name, username)
		 FROM users WHERE LOWER(username) = LOWER(?) AND is_banned = 0`,
		email,
	).Scan(&existingUserID, &existingName)
	if err == nil {
		mergeToken := randToken()
		expiresAt := time.Now().UTC().Add(10 * time.Minute).Format("2006-01-02 15:04:05")
		_, err2 := h.db.ExecContext(ctx,
			`INSERT INTO freja_merge_confirmations
			 (token, existing_user_id, freja_sub, freja_email, freja_name, expires_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			mergeToken, existingUserID, sub, email, name, expiresAt,
		)
		if err2 != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, frejaMergeConfirmHTML, existingName, email, mergeToken)
		return
	}

	// 3. No account found.
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, frejaNoAccountHTML, email)
}

// frejaConfirmMerge — POST /auth/freja/confirm-merge
func (h *Handler) frejaConfirmMerge(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	ctx := r.Context()

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	var userID, sub, email string
	err := h.db.QueryRowContext(ctx,
		`DELETE FROM freja_merge_confirmations
		 WHERE token = ? AND expires_at > ?
		 RETURNING existing_user_id, freja_sub, freja_email`,
		token, now,
	).Scan(&userID, &sub, &email)
	if err != nil {
		http.Error(w, "Link expired or invalid — please try logging in again.", http.StatusBadRequest)
		return
	}

	_, err = h.db.ExecContext(ctx,
		`INSERT INTO user_identities (id, user_id, provider, provider_subject, provider_email)
		 VALUES (?, ?, 'freja', ?, ?)
		 ON CONFLICT (provider, provider_subject) DO NOTHING`,
		uuid.NewString(), userID, sub, email,
	)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	if err := CreateSession(ctx, h.db, w, r, userID, h.isProd); err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// frejaLink — GET /auth/freja/link (authenticated, Apache-protected)
func (h *Handler) frejaLink(w http.ResponseWriter, r *http.Request) {
	email := frejaEmail(r)
	sub := frejaSub(r)
	userID := middleware.GetUserID(r)

	if email == "" {
		http.Error(w, "No authenticated email received from Freja eID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	var existingUserID string
	err := h.db.QueryRowContext(ctx,
		`SELECT user_id FROM user_identities
		 WHERE provider = 'freja'
		   AND (provider_subject = ? OR LOWER(provider_email) = LOWER(?))`,
		sub, email,
	).Scan(&existingUserID)
	if err == nil {
		if existingUserID == userID {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, frejaAlreadyLinkedHTML)
			return
		}
		http.Error(w, "This Freja eID is already linked to a different account.", http.StatusConflict)
		return
	}

	linkToken := randToken()
	expiresAt := time.Now().UTC().Add(10 * time.Minute).Format("2006-01-02 15:04:05")
	_, err = h.db.ExecContext(ctx,
		`INSERT INTO freja_link_confirmations
		 (token, user_id, freja_sub, freja_email, freja_name, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		linkToken, userID, sub, email, frejaName(r), expiresAt,
	)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, frejaLinkConfirmHTML, email, linkToken)
}

// frejaLinkConfirm — POST /auth/freja/link/confirm (authenticated)
func (h *Handler) frejaLinkConfirm(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	userID := middleware.GetUserID(r)
	ctx := r.Context()

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	var sub, email string
	err := h.db.QueryRowContext(ctx,
		`DELETE FROM freja_link_confirmations
		 WHERE token = ? AND user_id = ? AND expires_at > ?
		 RETURNING freja_sub, freja_email`,
		token, userID, now,
	).Scan(&sub, &email)
	if err != nil {
		http.Error(w, "Link expired or invalid — please try again.", http.StatusBadRequest)
		return
	}

	_, err = h.db.ExecContext(ctx,
		`INSERT INTO user_identities (id, user_id, provider, provider_subject, provider_email)
		 VALUES (?, ?, 'freja', ?, ?)
		 ON CONFLICT (provider, provider_subject) DO NOTHING`,
		uuid.NewString(), userID, sub, email,
	)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/settings/account?linked=freja", http.StatusSeeOther)
}

// frejaUnlink — POST /settings/freja/unlink (authenticated)
func (h *Handler) frejaUnlink(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	ctx := r.Context()

	var passkeyCount int
	h.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`, userID,
	).Scan(&passkeyCount)
	if passkeyCount == 0 {
		http.Error(w, "Cannot unlink Freja eID: you have no passkey to fall back to. Add a passkey first.", http.StatusBadRequest)
		return
	}

	h.db.ExecContext(ctx,
		`DELETE FROM user_identities WHERE user_id = ? AND provider = 'freja'`, userID,
	)
	http.Redirect(w, r, "/settings/account?unlinked=freja", http.StatusSeeOther)
}

// Inline HTML — only needs sql.NullString indirectly via the db queries above
var _ *sql.NullString

const frejaEmailMismatchHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Email mismatch — FrejaID Demo</title>
<link rel="stylesheet" href="/static/css/site.css"></head>
<body>
<header class="site-header"><div class="site-header__inner"><a href="/auth/login" class="site-logo">FrejaID Demo</a></div></header>
<main class="site-main">
  <h2>Email address mismatch</h2>
  <p>Your Freja eID is registered as <strong>%s</strong>, but you requested access with <strong>%s</strong>.</p>
  <p>Please go back and request access using the same email as your Freja eID, or choose "Set up a passkey" instead.</p>
  <p><a href="/auth/login">Back to login</a></p>
</main>
<footer class="site-footer"><p>FrejaID Demo</p></footer>
</body></html>`

const frejaMergeConfirmHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Link Freja eID — FrejaID Demo</title>
<link rel="stylesheet" href="/static/css/site.css"></head>
<body>
<header class="site-header"><div class="site-header__inner"><a href="/auth/login" class="site-logo">FrejaID Demo</a></div></header>
<main class="site-main">
  <h2>Link Freja eID to your account?</h2>
  <p>We found an existing account for <strong>%s</strong> with the email <strong>%s</strong>.</p>
  <p>Would you like to link your Freja eID to that account so you can use either method to log in?</p>
  <form method="POST" action="/auth/freja/confirm-merge">
    <input type="hidden" name="token" value="%s">
    <button type="submit">Yes, link my Freja eID</button>
  </form>
  <p><a href="/auth/login">No, go back to login</a></p>
</main>
<footer class="site-footer"><p>FrejaID Demo</p></footer>
</body></html>`

const frejaNoAccountHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>No account found — FrejaID Demo</title>
<link rel="stylesheet" href="/static/css/site.css"></head>
<body>
<header class="site-header"><div class="site-header__inner"><a href="/auth/login" class="site-logo">FrejaID Demo</a></div></header>
<main class="site-main">
  <h2>No account found</h2>
  <p>No account exists for the Freja eID email <strong>%s</strong>.</p>
  <p><a href="/auth/request">Request an account</a> — you can choose Freja eID during sign-up.</p>
  <p><a href="/auth/login">Back to login</a></p>
</main>
<footer class="site-footer"><p>FrejaID Demo</p></footer>
</body></html>`

const frejaAlreadyLinkedHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Already linked — FrejaID Demo</title>
<link rel="stylesheet" href="/static/css/site.css"></head>
<body>
<header class="site-header"><div class="site-header__inner"><a href="/" class="site-logo">FrejaID Demo</a></div></header>
<main class="site-main">
  <h2>Already linked</h2>
  <p>Your Freja eID is already linked to this account.</p>
  <p><a href="/settings/account">Back to account settings</a></p>
</main>
<footer class="site-footer"><p>FrejaID Demo</p></footer>
</body></html>`

const frejaLinkConfirmHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Link Freja eID — FrejaID Demo</title>
<link rel="stylesheet" href="/static/css/site.css"></head>
<body>
<header class="site-header"><div class="site-header__inner"><a href="/" class="site-logo">FrejaID Demo</a></div></header>
<main class="site-main">
  <h2>Link Freja eID to your account?</h2>
  <p>This will allow you to log in using your Freja eID (<strong>%s</strong>) as well as your passkey.</p>
  <form method="POST" action="/auth/freja/link/confirm">
    <input type="hidden" name="token" value="%s">
    <button type="submit">Yes, link Freja eID</button>
  </form>
  <p><a href="/settings/account">Cancel</a></p>
</main>
<footer class="site-footer"><p>FrejaID Demo</p></footer>
</body></html>`
