// Freja eID integration.
//
// Freja eID is a Swedish mobile identity app that supports OpenID Connect
// (OIDC).  Authentication is handled entirely by Apache's mod_auth_openidc
// module — the Go app never speaks OIDC directly.
//
// How it works:
//
//   Browser ──► Apache (mod_auth_openidc)
//                  │ OIDC redirect to Freja
//                  ↓
//               Freja app on user's phone
//                  │ OIDC callback to Apache
//                  ↓
//               Apache validates token, then proxies to Go with headers:
//                  X-Remote-User: user@example.com  (email claim)
//                  X-Freja-Sub:   <opaque subject>  (stable unique ID)
//                  X-Freja-Name:  Alice Svensson    (display name)
//
// The Go app reads these three headers and treats them as authoritative
// because the request comes from Apache on the loopback interface.
//
// Apache configuration (see config/apache-frejaid-le-ssl.conf):
//   - All paths under /auth/freja/* require Freja authentication.
//   - Unauthenticated requests are redirected to the Freja OIDC flow.
//   - After authentication, Apache proxies the request to Go and sets headers.
//
// Freja identity lookup order (login):
//   1. Match by provider_subject (the "sub" claim) — most reliable.
//   2. Match by provider_email — fallback if the subject changed.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/paftech/frejaid/internal/hooks"
	"github.com/paftech/frejaid/internal/middleware"
)

// frejaEmail returns the email address set by Apache in X-Remote-User.
func frejaEmail(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Remote-User"))
}

// frejaName returns the display name set by Apache in X-Freja-Name.
func frejaName(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Freja-Name"))
}

// frejaSub returns the stable subject identifier set by Apache in X-Freja-Sub.
// This is an opaque string from Freja that uniquely identifies the user.
// It is more reliable than the email because it does not change when the user
// updates their email address in the Freja app.
func frejaSub(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Freja-Sub"))
}

// randToken generates a 32-character hex string (16 random bytes) for use
// as a short-lived confirmation token.
func randToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// frejaRegister handles GET /auth/freja/register?token=…
//
// This path is Apache-protected: Apache has already authenticated the user
// with Freja eID and set the identity headers before the request reaches Go.
//
// Flow:
//   1. User chose "Continue with Freja eID" on /auth/choose (token in URL).
//   2. Browser followed the link to /auth/freja/register?token=…
//   3. Apache required Freja authentication (OIDC redirect to Freja app).
//   4. User approved in Freja app; Apache redirected back here with headers set.
//   5. We validate that the Freja email matches the registration email,
//      store the Freja subject in the registration row, and redirect to /auth/pending.
//
// Email mismatch: if the user authenticated to Freja with a different email
// than the one they registered with, we show an error.  They must either
// use a passkey instead or re-register with the Freja email.
func (h *Handler) frejaRegister(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	email := frejaEmail(r) // email from Freja via Apache header
	name := frejaName(r)
	sub := frejaSub(r)

	if email == "" {
		// This should not happen if Apache is configured correctly.
		http.Error(w, "No authenticated email received from Freja eID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	now := time.Now().UTC().Format("2006-01-02 15:04:05")

	// Look up the pending registration using the setup_token.
	var reqID, reqEmail, reqName string
	err := h.db.QueryRowContext(ctx,
		`SELECT id, email, name FROM registration_requests
		 WHERE setup_token = ? AND setup_token_expires_at > ?
		   AND status = 'pending' AND email_verified = 1`,
		token, now,
	).Scan(&reqID, &reqEmail, &reqName)
	if err != nil {
		http.Error(w, "Invalid or expired link", http.StatusBadRequest)
		return
	}

	// The email on the Freja identity MUST match the registration email.
	// If it does not, the user authenticated with the wrong Freja account.
	if !strings.EqualFold(email, reqEmail) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, frejaEmailMismatchHTML, html.EscapeString(email), html.EscapeString(reqEmail))
		return
	}

	// If Freja provided a name and the registration has none, fill it in.
	if name != "" && reqName == "" {
		h.db.ExecContext(ctx, `UPDATE registration_requests SET name = ? WHERE id = ?`, name, reqID)
	}

	// Mark this registration as a Freja registration and record the subject.
	// credential_submitted_at is used to filter registrations ready for admin review.
	_, err = h.db.ExecContext(ctx,
		`UPDATE registration_requests
		 SET provider = 'freja', freja_sub = ?, credential_submitted_at = datetime('now')
		 WHERE id = ?`,
		sub, reqID,
	)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Auto-approve if the email is in the ADMIN_EMAIL bootstrap list.
	if userID, ok := h.maybeAutoApprove(ctx, reqID, reqEmail); ok {
		if err := CreateSession(ctx, h.db, w, r, userID, h.isProd); err != nil {
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/auth/pending", http.StatusSeeOther)
}

// frejaLogin handles GET /auth/freja/login
//
// Apache-protected: Freja authentication happens before the request arrives.
//
// Three possible outcomes:
//   1. Known Freja identity → create session and log in (happy path).
//   2. Account exists with this email but no Freja identity linked → instruct
//      the user to log in with their passkey first, then link from settings.
//   3. No account found → show a link to the registration form.
func (h *Handler) frejaLogin(w http.ResponseWriter, r *http.Request) {
	email := frejaEmail(r)
	sub := frejaSub(r)

	if email == "" {
		http.Error(w, "No authenticated email received from Freja eID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// 1. Look up by subject — the stable, opaque identifier from Freja.
	var userID string
	err := h.db.QueryRowContext(ctx,
		`SELECT user_id FROM user_identities WHERE provider = 'freja' AND provider_subject = ?`,
		sub,
	).Scan(&userID)

	if err != nil && sub != "" {
		// Fallback: look up by email.  This handles accounts created before the
		// subject was stored, or a rare Freja subject rotation.  When we find a
		// match we immediately update the stored subject so future logins use it.
		err = h.db.QueryRowContext(ctx,
			`SELECT user_id FROM user_identities WHERE provider = 'freja' AND LOWER(provider_email) = LOWER(?)`,
			email,
		).Scan(&userID)
		if err == nil {
			// WARN: email fallback used — the stored subject did not match.
			// This is a self-healing path: we update the subject so future
			// logins use the stable sub claim.  Causes: account created before
			// sub storage, or a Freja subject rotation (rare).
			log.Printf("WARN freja login: subject lookup failed, email fallback matched %s — storing new subject %q", email, sub)
			h.db.ExecContext(ctx,
				`UPDATE user_identities SET provider_subject = ? WHERE user_id = ? AND provider = 'freja'`,
				sub, userID,
			)
		}
	}

	if err == nil {
		// Known identity — log in directly.
		if err2 := CreateSession(ctx, h.db, w, r, userID, h.isProd); err2 != nil {
			http.Error(w, "Session error", http.StatusInternalServerError)
			return
		}
		h.hooks.CallOnLogin(ctx, userID, hooks.LoginFreja)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// 2. Check if an account exists with this email but no Freja identity.
	//    The user must log in with their passkey and link Freja from settings.
	var existingCount int
	h.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER(?) AND is_banned = 0`,
		email,
	).Scan(&existingCount)
	if existingCount > 0 {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, frejaLoginExistingAccountHTML, html.EscapeString(email))
		return
	}

	// 3. No account at all.
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, frejaNoAccountHTML, html.EscapeString(email))
}

// frejaLink handles GET /auth/freja/link (authenticated, Apache-protected).
//
// Called when a logged-in user wants to add Freja eID as a second login method.
// Apache requires Freja authentication before the request reaches Go, so the
// Freja identity is already in the headers.
//
// We do not link immediately because the Freja OIDC redirect and the user's
// existing session cookie arrive in the same request, but we still want the
// user to explicitly confirm the link.  A short-lived token (freja_link_confirmations)
// bridges the two steps.
func (h *Handler) frejaLink(w http.ResponseWriter, r *http.Request) {
	email := frejaEmail(r)
	sub := frejaSub(r)
	userID := middleware.GetUserID(r) // the currently logged-in user

	if email == "" {
		http.Error(w, "No authenticated email received from Freja eID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Check if this Freja identity is already linked to any account.
	var existingUserID string
	err := h.db.QueryRowContext(ctx,
		`SELECT user_id FROM user_identities
		 WHERE provider = 'freja'
		   AND (provider_subject = ? OR LOWER(provider_email) = LOWER(?))`,
		sub, email,
	).Scan(&existingUserID)
	if err == nil {
		if existingUserID == userID {
			// Already linked to this account — show a confirmation.
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, frejaAlreadyLinkedHTML)
			return
		}
		// Linked to a different account — this is a conflict.
		http.Error(w, "This Freja eID is already linked to a different account.", http.StatusConflict)
		return
	}

	// Store the Freja identity temporarily.  The user will confirm on the next page.
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
	fmt.Fprintf(w, frejaLinkConfirmHTML, html.EscapeString(email), linkToken)
}

// frejaLinkConfirm handles POST /auth/freja/link/confirm (authenticated).
//
// The user has reviewed the "Link Freja eID?" confirmation page and submitted.
// We consume the token, write the identity to user_identities, and redirect.
func (h *Handler) frejaLinkConfirm(w http.ResponseWriter, r *http.Request) {
	if !ValidateCSRF(w, r) {
		return
	}
	token := r.FormValue("token")
	userID := middleware.GetUserID(r)
	ctx := r.Context()

	// Delete the token atomically and return the Freja identity.
	// If the token is expired or belongs to a different user, this returns an error.
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

	h.hooks.CallOnFrejaLinked(ctx, userID, email, sub)

	http.Redirect(w, r, "/settings/account?linked=freja", http.StatusSeeOther)
}

// frejaUnlink handles POST /settings/freja/unlink (authenticated).
//
// Removes the Freja eID from the user's account.
// Requires at least one passkey to remain, so the user can still log in.
func (h *Handler) frejaUnlink(w http.ResponseWriter, r *http.Request) {
	if !ValidateCSRF(w, r) {
		return
	}
	userID := middleware.GetUserID(r)
	ctx := r.Context()

	// Safety check: do not unlink if the user has no passkeys, because that
	// would leave them with no way to log in.
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
	h.hooks.CallOnFrejaUnlinked(ctx, userID)
	http.Redirect(w, r, "/settings/account?unlinked=freja", http.StatusSeeOther)
}

// ─── Inline HTML templates ───────────────────────────────────────────────────

// frejaEmailMismatchHTML is shown when the Freja-authenticated email does not
// match the email on the registration request.
// Format args: %s = Freja email, %s = registration email.
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

// frejaLoginExistingAccountHTML is shown when a Freja login arrives for an
// email that has an account but no Freja identity linked.
// Format arg: %s = email.
const frejaLoginExistingAccountHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Account already exists — FrejaID Demo</title>
<link rel="stylesheet" href="/static/css/site.css"></head>
<body>
<header class="site-header"><div class="site-header__inner"><a href="/auth/login" class="site-logo">FrejaID Demo</a></div></header>
<main class="site-main">
  <h2>Account already exists</h2>
  <p>An account with the email <strong>%s</strong> already exists.</p>
  <p><a href="/auth/login">Log in with your passkey</a>, then add Freja eID from <strong>Account Settings → Login methods</strong>.</p>
</main>
<footer class="site-footer"><p>FrejaID Demo</p></footer>
</body></html>`

// frejaNoAccountHTML is shown when a Freja login arrives but no account exists.
// Format arg: %s = email.
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

// frejaAlreadyLinkedHTML is shown when the user tries to link a Freja identity
// that is already linked to their account.
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

// frejaLinkConfirmHTML asks the user to confirm linking their Freja identity.
// Format args: %s = Freja email, %s = link token.
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
