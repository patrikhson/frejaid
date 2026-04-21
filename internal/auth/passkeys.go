package auth

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/paftech/frejaid/internal/layout"
	"github.com/paftech/frejaid/internal/middleware"
)

type passkeyRow struct {
	ID          string
	Name        string
	CreatedAt   string
	LastUsedAt  sql.NullString
}

func (h *Handler) showPasskeys(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	role := middleware.GetUserRole(r)
	ctx := r.Context()

	rows, err := h.db.QueryContext(ctx,
		`SELECT id, COALESCE(name,''), created_at, last_used_at
		 FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at`,
		userID,
	)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var creds []passkeyRow
	for rows.Next() {
		var p passkeyRow
		rows.Scan(&p.ID, &p.Name, &p.CreatedAt, &p.LastUsedAt)
		creds = append(creds, p)
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, layout.PageStart("Passkeys", role, ""))
	fmt.Fprint(w, `<h2>Passkeys</h2>`)
	fmt.Fprint(w, `<p><a href="/settings/account">← Account settings</a></p>`)

	if len(creds) == 0 {
		fmt.Fprint(w, `<p>No passkeys found.</p>`)
	} else {
		fmt.Fprint(w, `<table><thead><tr><th>Name</th><th>Added</th><th>Last used</th><th></th></tr></thead><tbody>`)
		for _, c := range creds {
			lastUsed := "never"
			if c.LastUsedAt.Valid && c.LastUsedAt.String != "" {
				if t, err := time.Parse("2006-01-02 15:04:05", c.LastUsedAt.String); err == nil {
					lastUsed = t.Format("2 Jan 2006")
				}
			}
			createdFmt := c.CreatedAt
			if t, err := time.Parse("2006-01-02 15:04:05", c.CreatedAt); err == nil {
				createdFmt = t.Format("2 Jan 2006")
			}
			deleteBtn := ""
			if len(creds) > 1 {
				deleteBtn = fmt.Sprintf(
					`<form method="POST" action="/settings/passkeys/%s/delete" style="display:inline" onsubmit="return confirm('Delete this passkey?')">
					   <button type="submit" class="btn-sm btn-danger">Delete</button>
					 </form>`,
					c.ID,
				)
			}
			fmt.Fprintf(w,
				`<tr>
				   <td>
				     <form method="POST" action="/settings/passkeys/%s/rename" style="display:flex;gap:0.4rem;align-items:center">
				       <input type="text" name="name" value="%s" required style="width:14rem">
				       <button type="submit" class="btn-sm">Rename</button>
				     </form>
				   </td>
				   <td>%s</td>
				   <td>%s</td>
				   <td>%s</td>
				 </tr>`,
				c.ID, htmlEscapeAttr(c.Name),
				createdFmt,
				lastUsed,
				deleteBtn,
			)
		}
		fmt.Fprint(w, `</tbody></table>`)
	}

	fmt.Fprint(w, `
<h3>Add a new passkey</h3>
<p>Register a passkey on another device — phone, laptop, or security key.</p>
<div class="form">
  <label>Passkey name (e.g. "iPhone 15" or "YubiKey")
    <input type="text" id="newPasskeyName" placeholder="My device" style="width:16rem">
  </label><br>
  <button id="addPasskeyBtn" class="btn-sm" style="margin-top:0.5rem">Add passkey</button>
  <p id="addPasskeyMsg" style="color:var(--color-error,red)"></p>
</div>
<script>
document.getElementById('addPasskeyBtn').addEventListener('click', async () => {
  const name = document.getElementById('newPasskeyName').value.trim();
  const msg = document.getElementById('addPasskeyMsg');
  msg.textContent = '';
  if (!name) { msg.textContent = 'Please enter a name first.'; return; }

  const beginResp = await fetch('/settings/passkeys/add/begin', {method: 'POST'});
  if (!beginResp.ok) { msg.textContent = await beginResp.text(); return; }

  const options = await beginResp.json();
  options.publicKey.challenge = base64ToBuffer(options.publicKey.challenge);
  options.publicKey.user.id = base64ToBuffer(options.publicKey.user.id);
  if (options.publicKey.excludeCredentials) {
    options.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(c => ({
      ...c, id: base64ToBuffer(c.id)
    }));
  }

  let credential;
  try {
    credential = await navigator.credentials.create(options);
  } catch (e) {
    msg.textContent = 'Passkey creation cancelled or failed: ' + e.message;
    return;
  }

  const finishResp = await fetch('/settings/passkeys/add/finish?name=' + encodeURIComponent(name), {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      id: credential.id,
      rawId: bufferToBase64(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: bufferToBase64(credential.response.attestationObject),
        clientDataJSON: bufferToBase64(credential.response.clientDataJSON),
      },
    }),
  });
  if (finishResp.ok) {
    window.location.reload();
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
`)
	fmt.Fprint(w, layout.PageEnd())
}

func (h *Handler) beginAddPasskey(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	ctx := r.Context()

	var displayName, email string
	h.db.QueryRowContext(ctx,
		`SELECT COALESCE(display_name,''), username FROM users WHERE id = ?`,
		userID,
	).Scan(&displayName, &email)

	waUser, err := h.loadWAUser(ctx, userID, displayName, email)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	options, sessionData, err := h.webAuthn.BeginRegistration(waUser)
	if err != nil {
		http.Error(w, "WebAuthn error: "+err.Error(), http.StatusInternalServerError)
		return
	}

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

func (h *Handler) finishAddPasskey(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		name = "Passkey"
	}
	ctx := r.Context()

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	var sessionJSONStr string
	err := h.db.QueryRowContext(ctx,
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

	var displayName, email string
	h.db.QueryRowContext(ctx,
		`SELECT COALESCE(display_name,''), username FROM users WHERE id = ?`,
		userID,
	).Scan(&displayName, &email)

	waUser, _ := h.loadWAUser(ctx, userID, displayName, email)
	credential, err := h.webAuthn.FinishRegistration(waUser, sd, r)
	if err != nil {
		http.Error(w, "Passkey registration failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	pubKey, _ := json.Marshal(credential.PublicKey)
	_, err = h.db.ExecContext(ctx,
		`INSERT INTO webauthn_credentials
		 (id, user_id, credential_id, public_key, aaguid, sign_count, backup_eligible, backup_state, name)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		uuid.NewString(), userID, credential.ID, pubKey,
		credential.Authenticator.AAGUID, credential.Authenticator.SignCount,
		credential.Flags.BackupEligible, credential.Flags.BackupState,
		name,
	)
	if err != nil {
		http.Error(w, "Failed to save passkey: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) renamePasskey(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	credID := r.PathValue("id")
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}
	h.db.ExecContext(r.Context(),
		`UPDATE webauthn_credentials SET name = ? WHERE id = ? AND user_id = ?`,
		name, credID, userID,
	)
	http.Redirect(w, r, "/settings/passkeys", http.StatusSeeOther)
}

func (h *Handler) deletePasskey(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)
	credID := r.PathValue("id")
	ctx := r.Context()

	var count int
	h.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`,
		userID,
	).Scan(&count)

	if count <= 1 {
		http.Error(w, "Cannot delete your only passkey", http.StatusBadRequest)
		return
	}

	h.db.ExecContext(ctx,
		`DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?`,
		credID, userID,
	)
	http.Redirect(w, r, "/settings/passkeys", http.StatusSeeOther)
}

func htmlEscapeAttr(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&#34;")
	return s
}
