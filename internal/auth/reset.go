// Credential reset flow.
//
// When a user loses access to their passkey (broken device, factory reset)
// or their Freja eID (changed phone number, new Freja account) they can
// request new credentials through this flow:
//
//   1. User visits the registration form with their email address.
//      If the account exists, they see the "Account already exists" page
//      which offers the option to request a credential reset.
//
//   2. User submits POST /auth/request-credential-reset with their email
//      and which credential type they need (passkey or Freja eID).
//      A credential_reset_requests row is created (status='pending').
//      All admins are notified by email.
//
//   3. Admin reviews the request in /admin/credential-resets and clicks Approve.
//      A 48-hour token is generated; the user receives an email with a link.
//
//   4a. Passkey reset: user visits GET /auth/reset-passkey?token=…
//       The page runs the standard WebAuthn registration ceremony.
//       A new passkey is added to their account; status='completed'.
//
//   4b. Freja reset: user visits GET /auth/reset-freja?token=…
//       This path is Apache-protected (mod_auth_openidc).
//       Apache authenticates the user with Freja, sets the identity headers,
//       and proxies to Go.  We verify the Freja email matches the account,
//       upsert the identity, log the user in, and set status='completed'.
package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// requestCredentialReset handles POST /auth/request-credential-reset.
// Creates a pending reset request and notifies admins.
func (h *Handler) requestCredentialReset(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
	provider := r.FormValue("provider")
	if provider != "passkey" && provider != "freja" {
		provider = "passkey"
	}

	ctx := r.Context()

	// Look up the account.  If not found, silently redirect to login to avoid
	// revealing whether an account exists for a given email.
	var userID string
	h.db.QueryRowContext(ctx, `SELECT id FROM users WHERE LOWER(username) = LOWER(?)`, email).Scan(&userID)
	if userID == "" {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	// Prevent duplicate pending requests for the same user + provider combination.
	// If one is already pending, just tell the user to wait.
	var existing int
	h.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM credential_reset_requests WHERE user_id=? AND provider=? AND status='pending'`,
		userID, provider,
	).Scan(&existing)
	if existing > 0 {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, publicPage("Request received",
			`<p>A request is already pending. An admin will review it and send you a setup link.</p>`))
		return
	}

	_, err := h.db.ExecContext(ctx,
		`INSERT INTO credential_reset_requests (id, user_id, provider) VALUES (?, ?, ?)`,
		uuid.NewString(), userID, provider,
	)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Notify all admins by email.
	var name string
	h.db.QueryRowContext(ctx, `SELECT COALESCE(display_name, username) FROM users WHERE id=?`, userID).Scan(&name)

	rows, _ := h.db.QueryContext(ctx, `SELECT username FROM users WHERE role='admin'`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var adminEmail string
			rows.Scan(&adminEmail)
			h.mailer.SendAdminCredentialReset(adminEmail, name, email)
		}
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, publicPage("Request received",
		`<p>Your request has been submitted. An admin will review it and send you a setup link.</p>`))
}

// showResetPasskey handles GET /auth/reset-passkey?token=…
// Validates the token and renders the passkey registration page.
func (h *Handler) showResetPasskey(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Invalid link", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	var name string
	err := h.db.QueryRowContext(r.Context(),
		`SELECT COALESCE(u.display_name, u.username)
		 FROM credential_reset_requests cr
		 JOIN users u ON u.id = cr.user_id
		 WHERE cr.setup_token = ? AND cr.token_expires_at > ? AND cr.status = 'approved' AND cr.provider = 'passkey'`,
		token, now,
	).Scan(&name)
	if err != nil {
		http.Error(w, "Invalid or expired link", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, resetPasskeyHTML, name, token)
}

// beginResetPasskey handles POST /auth/reset-passkey/begin?token=…
//
// Starts the WebAuthn registration ceremony for a credential reset.
// This is the same BeginRegistration call as the initial sign-up, but the
// user is identified by the reset token rather than a session.
//
// We load the user's existing credentials so they appear in excludeCredentials
// in the registration options, preventing the device from registering a key
// that is already stored (the user is adding a NEW credential, not re-registering
// the same one).
func (h *Handler) beginResetPasskey(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	ctx := r.Context()

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	var userID, name, email string
	err := h.db.QueryRowContext(ctx,
		`SELECT cr.user_id, COALESCE(u.display_name, u.username), u.username
		 FROM credential_reset_requests cr
		 JOIN users u ON u.id = cr.user_id
		 WHERE cr.setup_token = ? AND cr.token_expires_at > ? AND cr.status = 'approved' AND cr.provider = 'passkey'`,
		token, now,
	).Scan(&userID, &name, &email)
	if err != nil {
		http.Error(w, "Invalid or expired link", http.StatusBadRequest)
		return
	}

	// Load existing credentials so BeginRegistration can populate excludeCredentials.
	waUser, err := h.loadWAUser(ctx, userID, name, email)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	options, sessionData, err := h.webAuthn.BeginRegistration(waUser)
	if err != nil {
		http.Error(w, "WebAuthn error", http.StatusInternalServerError)
		return
	}

	// Store the challenge for 5 minutes.  We reuse webauthn_add_sessions
	// (same table used when adding a second passkey from settings).
	sessionJSON, _ := json.Marshal(sessionData)
	expiresAt := time.Now().UTC().Add(5 * time.Minute).Format("2006-01-02 15:04:05")
	h.db.ExecContext(ctx,
		`INSERT INTO webauthn_add_sessions (user_id, session_data, expires_at)
		 VALUES (?, ?, ?)
		 ON CONFLICT (user_id) DO UPDATE SET session_data = excluded.session_data, expires_at = excluded.expires_at`,
		userID, string(sessionJSON), expiresAt,
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// finishResetPasskey handles POST /auth/reset-passkey/finish?token=…
//
// Completes the WebAuthn registration, stores the new credential, marks the
// reset request as completed.  The user still needs to log in normally.
func (h *Handler) finishResetPasskey(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	ctx := r.Context()

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	var resetID, userID, name, email string
	err := h.db.QueryRowContext(ctx,
		`SELECT cr.id, cr.user_id, COALESCE(u.display_name, u.username), u.username
		 FROM credential_reset_requests cr
		 JOIN users u ON u.id = cr.user_id
		 WHERE cr.setup_token = ? AND cr.token_expires_at > ? AND cr.status = 'approved' AND cr.provider = 'passkey'`,
		token, now,
	).Scan(&resetID, &userID, &name, &email)
	if err != nil {
		http.Error(w, "Invalid or expired link", http.StatusBadRequest)
		return
	}

	// Delete the session row atomically and return the session data.
	var sessionJSONStr string
	err = h.db.QueryRowContext(ctx,
		`DELETE FROM webauthn_add_sessions WHERE user_id = ? AND expires_at > ? RETURNING session_data`,
		userID, now,
	).Scan(&sessionJSONStr)
	if err != nil {
		http.Error(w, "Session expired, please try again", http.StatusBadRequest)
		return
	}

	var sd webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionJSONStr), &sd); err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	waUser, _ := h.loadWAUser(ctx, userID, name, email)

	// Verify the authenticator's response against the stored challenge.
	credential, err := h.webAuthn.FinishRegistration(waUser, sd, r)
	if err != nil {
		http.Error(w, "Passkey registration failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Insert the new passkey.  The user now has this credential in addition to
	// any existing ones (or instead of, if all old ones were lost/deleted).
	pubKey, _ := json.Marshal(credential.PublicKey)
	_, err = h.db.ExecContext(ctx,
		`INSERT INTO webauthn_credentials
		 (id, user_id, credential_id, public_key, aaguid, sign_count, backup_eligible, backup_state, name)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Reset passkey')`,
		uuid.NewString(), userID, credential.ID, pubKey,
		credential.Authenticator.AAGUID, credential.Authenticator.SignCount,
		credential.Flags.BackupEligible, credential.Flags.BackupState,
	)
	if err != nil {
		http.Error(w, "Failed to save passkey: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.db.ExecContext(ctx, `UPDATE credential_reset_requests SET status='completed' WHERE id=?`, resetID)

	// Return 200 OK; the JS on the reset page redirects to /auth/login.
	w.WriteHeader(http.StatusOK)
}

// resetFreja handles GET /auth/reset-freja?token=…
//
// Apache-protected: Apache performs Freja eID authentication before the
// request reaches Go, and sets X-Remote-User and X-Freja-Sub headers.
//
// We verify:
//   a) The token is valid and not expired.
//   b) The Freja email matches the account email (to prove identity).
//
// On success, the Freja identity is upserted into user_identities and
// the user is logged in immediately.
func (h *Handler) resetFreja(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	frejaEm := frejaEmail(r) // email from Freja via Apache header
	frejaSb := frejaSub(r)   // subject from Freja via Apache header

	if frejaEm == "" {
		http.Error(w, "No authenticated email received from Freja eID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	now := time.Now().UTC().Format("2006-01-02 15:04:05")

	// Validate the token and retrieve the account details.
	var resetID, userID, userEmail string
	err := h.db.QueryRowContext(ctx,
		`SELECT cr.id, cr.user_id, u.username
		 FROM credential_reset_requests cr
		 JOIN users u ON u.id = cr.user_id
		 WHERE cr.setup_token = ? AND cr.token_expires_at > ? AND cr.status = 'approved' AND cr.provider = 'freja'`,
		token, now,
	).Scan(&resetID, &userID, &userEmail)
	if err != nil {
		http.Error(w, "Invalid or expired link", http.StatusBadRequest)
		return
	}

	// The Freja email must match the account email.  This prevents someone
	// from using another person's reset link with their own Freja identity.
	if !strings.EqualFold(frejaEm, userEmail) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, frejaEmailMismatchHTML, frejaEm, userEmail)
		return
	}

	// Upsert the Freja identity.  If a row already exists for this subject
	// (e.g. a previous link was made), update the email in case it changed.
	_, err = h.db.ExecContext(ctx,
		`INSERT INTO user_identities (id, user_id, provider, provider_subject, provider_email)
		 VALUES (?, ?, 'freja', ?, ?)
		 ON CONFLICT (provider, provider_subject) DO UPDATE SET provider_email = excluded.provider_email`,
		uuid.NewString(), userID, frejaSb, frejaEm,
	)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	h.db.ExecContext(ctx, `UPDATE credential_reset_requests SET status='completed' WHERE id=?`, resetID)

	// Log the user in directly — they have just proved their identity via Freja.
	if err := CreateSession(ctx, h.db, w, r, userID, h.isProd); err != nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// resetPasskeyHTML is the page for the passkey reset flow.
// It uses the same WebAuthn registration JS as the initial sign-up
// (navigator.credentials.create) but posts to the reset-specific endpoints.
// Format args: %s = display name, %q = token (Go-quoted for safe JS embedding).
var resetPasskeyHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Set up new passkey — FrejaID Demo</title>
  <link rel="stylesheet" href="/static/css/site.css">
</head>
<body>
<header class="site-header">
  <div class="site-header__inner">
    <a href="/auth/login" class="site-logo">FrejaID Demo</a>
  </div>
</header>
<main class="site-main">
<h2>Welcome back, %s!</h2>
<p>Set up your new passkey. You can use Face ID, Touch ID, or a security key.</p>
<button id="registerBtn" class="btn">Set up passkey</button>
<p id="msg" style="color:var(--color-error,red)"></p>
<script>
const token = %q;
document.getElementById('registerBtn').addEventListener('click', async () => {
  const msg = document.getElementById('msg');
  msg.textContent = '';

  // Step 1: get registration options (challenge, excludeCredentials, etc.).
  const beginResp = await fetch('/auth/reset-passkey/begin?token=' + token, {method: 'POST'});
  if (!beginResp.ok) { msg.textContent = await beginResp.text(); return; }

  const options = await beginResp.json();
  options.publicKey.challenge = base64ToBuffer(options.publicKey.challenge);
  options.publicKey.user.id   = base64ToBuffer(options.publicKey.user.id);
  if (options.publicKey.excludeCredentials) {
    options.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(c => ({
      ...c, id: base64ToBuffer(c.id)
    }));
  }

  // Step 2: create a new passkey on this device.
  let credential;
  try {
    credential = await navigator.credentials.create(options);
  } catch (e) {
    msg.textContent = 'Passkey creation cancelled or failed: ' + e.message;
    return;
  }

  // Step 3: send the public key to the server.
  const finishResp = await fetch('/auth/reset-passkey/finish?token=' + token, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      id:     credential.id,
      rawId:  bufferToBase64(credential.rawId),
      type:   credential.type,
      response: {
        attestationObject: bufferToBase64(credential.response.attestationObject),
        clientDataJSON:    bufferToBase64(credential.response.clientDataJSON),
      },
    }),
  });
  if (finishResp.ok) {
    window.location.href = '/auth/login';
  } else {
    msg.textContent = await finishResp.text();
  }
});

function base64ToBuffer(b64) {
  const s = atob(b64.replace(/-/g,'+').replace(/_/g,'/'));
  return Uint8Array.from(s, c => c.charCodeAt(0)).buffer;
}
function bufferToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
</script>
</main>
<footer class="site-footer"><p>FrejaID Demo</p></footer>
</body></html>`
