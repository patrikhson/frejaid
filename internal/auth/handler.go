package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/paftech/frejaid/internal/mail"
)

type Handler struct {
	db         *sql.DB
	webAuthn   *webauthn.WebAuthn
	mailer     *mail.Mailer
	baseURL    string
	isProd     bool
	sessionKey string
}

func NewHandler(db *sql.DB, wa *webauthn.WebAuthn, mailer *mail.Mailer, baseURL, sessionKey string, isProd bool) *Handler {
	return &Handler{
		db:         db,
		webAuthn:   wa,
		mailer:     mailer,
		baseURL:    baseURL,
		isProd:     isProd,
		sessionKey: sessionKey,
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, requireAuth func(http.Handler) http.Handler) {
	mux.HandleFunc("GET /auth/request", h.showRequestForm)
	mux.HandleFunc("POST /auth/request", h.submitRequest)
	mux.HandleFunc("GET /auth/verify-email", h.showVerifyEmail)
	mux.HandleFunc("POST /auth/verify-email", h.verifyEmail)

	mux.HandleFunc("GET /auth/choose", h.showChoose)

	mux.HandleFunc("GET /auth/register", h.showRegisterPasskey)
	mux.HandleFunc("POST /auth/register/begin", h.beginRegisterPasskey)
	mux.HandleFunc("POST /auth/register/finish", h.finishRegisterPasskey)

	mux.HandleFunc("GET /auth/freja/register", h.frejaRegister)
	mux.HandleFunc("GET /auth/freja/login", h.frejaLogin)
	mux.HandleFunc("POST /auth/freja/confirm-merge", h.frejaConfirmMerge)

	mux.HandleFunc("GET /auth/pending", h.showPending)

	mux.HandleFunc("GET /auth/login", h.showLogin)
	mux.HandleFunc("POST /auth/login/begin", h.beginLogin)
	mux.HandleFunc("POST /auth/login/finish", h.finishLogin)

	mux.HandleFunc("POST /auth/logout", h.logout)

	mux.Handle("GET /settings/passkeys", requireAuth(http.HandlerFunc(h.showPasskeys)))
	mux.Handle("POST /settings/passkeys/add/begin", requireAuth(http.HandlerFunc(h.beginAddPasskey)))
	mux.Handle("POST /settings/passkeys/add/finish", requireAuth(http.HandlerFunc(h.finishAddPasskey)))
	mux.Handle("POST /settings/passkeys/{id}/rename", requireAuth(http.HandlerFunc(h.renamePasskey)))
	mux.Handle("POST /settings/passkeys/{id}/delete", requireAuth(http.HandlerFunc(h.deletePasskey)))

	mux.Handle("GET /auth/freja/link", requireAuth(http.HandlerFunc(h.frejaLink)))
	mux.Handle("POST /auth/freja/link/confirm", requireAuth(http.HandlerFunc(h.frejaLinkConfirm)))

	mux.Handle("POST /settings/freja/unlink", requireAuth(http.HandlerFunc(h.frejaUnlink)))
}

func (h *Handler) showRequestForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, requestFormHTML)
}

func (h *Handler) submitRequest(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	email := r.FormValue("email")

	if name == "" || email == "" {
		http.Error(w, "Name and email are required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	var exists bool
	h.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM registration_requests WHERE email = ?)`, email).Scan(&exists)
	if exists {
		h.showRequestSuccess(w, r)
		return
	}

	token := uuid.NewString()
	pendingUserID := uuid.NewString()
	expiresAt := time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02 15:04:05")
	_, err := h.db.ExecContext(ctx,
		`INSERT INTO registration_requests (id, token, name, email, expires_at, pending_user_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		uuid.NewString(), token, name, email, expiresAt, pendingUserID,
	)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	link := h.baseURL + "/auth/verify-email?token=" + token
	if err := h.mailer.SendVerification(email, name, link); err != nil {
		fmt.Printf("mail error: %v\n", err)
	}

	h.showRequestSuccess(w, r)
}

func (h *Handler) showRequestSuccess(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, publicPage("Check your email",
		`<p>If that email address is valid, we've sent a verification link. Check your inbox.</p>`))
}

func (h *Handler) showVerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Invalid link", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, verifyEmailHTML, token)
}

func (h *Handler) verifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	if token == "" {
		http.Error(w, "Invalid link", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	passkeyToken := uuid.NewString()
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	expiresAt := time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02 15:04:05")
	res, err := h.db.ExecContext(ctx,
		`UPDATE registration_requests
		 SET email_verified = 1, email_verified_at = ?,
		     passkey_token = ?, passkey_token_expires_at = ?
		 WHERE token = ? AND expires_at > ? AND email_verified = 0`,
		now, passkeyToken, expiresAt, token, now,
	)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "Invalid or expired link", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/auth/choose?token="+passkeyToken, http.StatusSeeOther)
}

func (h *Handler) SendApprovalEmail(ctx context.Context, requestID string) (string, error) {
	return SendApprovalEmail(ctx, h.db, h.mailer, h.baseURL, requestID)
}

func SendApprovalEmail(ctx context.Context, db *sql.DB, mailer *mail.Mailer, baseURL, requestID string) (string, error) {
	var name, email, pendingUserID, provider string
	var frejaSub sql.NullString
	var credJSON sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT name, email, pending_user_id, provider, freja_sub, pending_credential
		 FROM registration_requests WHERE id = ? AND status = 'pending'`,
		requestID,
	).Scan(&name, &email, &pendingUserID, &provider, &frejaSub, &credJSON)
	if err != nil {
		return "", fmt.Errorf("registration not found: %w", err)
	}

	if provider == "freja" {
		return sendApprovalFreja(ctx, db, mailer, baseURL, requestID, pendingUserID, name, email, frejaSub)
	}
	return sendApprovalPasskey(ctx, db, mailer, baseURL, requestID, pendingUserID, name, email, credJSON)
}

func sendApprovalPasskey(ctx context.Context, db *sql.DB, mailer *mail.Mailer, baseURL, requestID, pendingUserID, name, email string, credJSON sql.NullString) (string, error) {
	if !credJSON.Valid || credJSON.String == "" {
		return "", fmt.Errorf("passkey not yet registered")
	}

	var cred storedCredential
	if err := json.Unmarshal([]byte(credJSON.String), &cred); err != nil {
		return "", fmt.Errorf("corrupt credential data: %w", err)
	}

	userID := pendingUserID
	_, err := db.ExecContext(ctx,
		`INSERT INTO users (id, username, display_name, role) VALUES (?, ?, ?, 'passive')`,
		userID, email, name,
	)
	if err != nil {
		return "", fmt.Errorf("create user: %w", err)
	}

	_, err = db.ExecContext(ctx,
		`INSERT INTO webauthn_credentials
		 (id, user_id, credential_id, public_key, aaguid, sign_count, backup_eligible, backup_state, name)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Primary passkey')`,
		uuid.NewString(), userID, cred.ID, cred.PublicKey, cred.AAGUID, cred.SignCount, cred.BackupEligible, cred.BackupState,
	)
	if err != nil {
		return "", fmt.Errorf("store credential: %w", err)
	}

	db.ExecContext(ctx,
		`UPDATE registration_requests SET status = 'completed', user_id = ? WHERE id = ?`,
		userID, requestID,
	)

	return userID, mailer.SendApproved(email, name, baseURL+"/auth/login")
}

func sendApprovalFreja(ctx context.Context, db *sql.DB, mailer *mail.Mailer, baseURL, requestID, pendingUserID, name, email string, frejaSub sql.NullString) (string, error) {
	userID := pendingUserID
	_, err := db.ExecContext(ctx,
		`INSERT INTO users (id, username, display_name, role) VALUES (?, ?, ?, 'passive')`,
		userID, email, name,
	)
	if err != nil {
		return "", fmt.Errorf("create user: %w", err)
	}

	sub := ""
	if frejaSub.Valid {
		sub = frejaSub.String
	}
	db.ExecContext(ctx,
		`INSERT INTO user_identities (id, user_id, provider, provider_subject, provider_email)
		 VALUES (?, ?, 'freja', ?, ?)
		 ON CONFLICT (provider, provider_subject) DO NOTHING`,
		uuid.NewString(), userID, sub, email,
	)

	db.ExecContext(ctx,
		`UPDATE registration_requests SET status = 'completed', user_id = ? WHERE id = ?`,
		userID, requestID,
	)

	return userID, mailer.SendApprovedFreja(email, name, baseURL+"/auth/login")
}

func (h *Handler) showChoose(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Invalid link", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	var name, email string
	err := h.db.QueryRowContext(r.Context(),
		`SELECT name, email FROM registration_requests
		 WHERE passkey_token = ? AND passkey_token_expires_at > ?
		   AND status = 'pending' AND email_verified = 1`,
		token, now,
	).Scan(&name, &email)
	if err != nil {
		http.Error(w, "Invalid or expired link", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, chooseMethodHTML, name, email, token, token)
}

func (h *Handler) showRegisterPasskey(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Invalid link", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	var name string
	err := h.db.QueryRowContext(r.Context(),
		`SELECT name FROM registration_requests
		 WHERE passkey_token = ? AND passkey_token_expires_at > ?
		   AND status = 'pending' AND email_verified = 1`,
		token, now,
	).Scan(&name)
	if err != nil {
		http.Error(w, "Invalid or expired link", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, registerPasskeyHTML, name, token)
}

func (h *Handler) beginRegisterPasskey(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	ctx := r.Context()

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	var reqID, name, email, pendingUserID string
	err := h.db.QueryRowContext(ctx,
		`SELECT id, name, email, pending_user_id FROM registration_requests
		 WHERE passkey_token = ? AND passkey_token_expires_at > ?
		   AND status = 'pending' AND email_verified = 1`,
		token, now,
	).Scan(&reqID, &name, &email, &pendingUserID)
	if err != nil {
		http.Error(w, "Invalid or expired link", http.StatusBadRequest)
		return
	}

	waUser := &waUser{id: pendingUserID, name: name, displayName: name, email: email}

	options, sessionData, err := h.webAuthn.BeginRegistration(waUser)
	if err != nil {
		http.Error(w, "WebAuthn error", http.StatusInternalServerError)
		return
	}

	sessionJSON, _ := json.Marshal(sessionData)
	h.db.ExecContext(ctx,
		`UPDATE registration_requests SET webauthn_session = ? WHERE id = ?`,
		string(sessionJSON), reqID,
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func (h *Handler) finishRegisterPasskey(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	ctx := r.Context()

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	var reqID, name, email, pendingUserID string
	var sessionJSONStr sql.NullString
	err := h.db.QueryRowContext(ctx,
		`SELECT id, name, email, pending_user_id, webauthn_session FROM registration_requests
		 WHERE passkey_token = ? AND passkey_token_expires_at > ?
		   AND status = 'pending' AND email_verified = 1`,
		token, now,
	).Scan(&reqID, &name, &email, &pendingUserID, &sessionJSONStr)
	if err != nil {
		http.Error(w, "Invalid or expired link", http.StatusBadRequest)
		return
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionJSONStr.String), &sessionData); err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	waUser := &waUser{id: pendingUserID, name: name, displayName: name, email: email}
	credential, err := h.webAuthn.FinishRegistration(waUser, sessionData, r)
	if err != nil {
		http.Error(w, "Passkey registration failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	pubKey, _ := json.Marshal(credential.PublicKey)
	stored := storedCredential{
		ID:             credential.ID,
		PublicKey:      pubKey,
		AAGUID:         credential.Authenticator.AAGUID,
		SignCount:      credential.Authenticator.SignCount,
		BackupEligible: credential.Flags.BackupEligible,
		BackupState:    credential.Flags.BackupState,
	}
	storedJSON, _ := json.Marshal(stored)
	h.db.ExecContext(ctx,
		`UPDATE registration_requests
		 SET pending_credential = ?, passkey_registered_at = datetime('now')
		 WHERE id = ?`,
		string(storedJSON), reqID,
	)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, publicPage("Request submitted",
		`<p>Your passkey is registered. You'll receive an email when an admin approves your account.</p>`))
}

type storedCredential struct {
	ID             []byte `json:"id"`
	PublicKey      []byte `json:"public_key"`
	AAGUID         []byte `json:"aaguid"`
	SignCount      uint32 `json:"sign_count"`
	BackupEligible bool   `json:"backup_eligible"`
	BackupState    bool   `json:"backup_state"`
}

func (h *Handler) showPending(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, publicPage("Pending approval",
		`<p>Your request is submitted. You'll receive an email when an admin approves your account.</p>`))
}

func (h *Handler) showLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, loginHTML)
}

func (h *Handler) beginLogin(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	ctx := r.Context()

	var userID, name string
	err := h.db.QueryRowContext(ctx,
		`SELECT id, COALESCE(display_name, username) FROM users WHERE username = ? AND is_banned = 0`,
		email,
	).Scan(&userID, &name)
	if err != nil {
		http.Error(w, "No passkey found for that email", http.StatusBadRequest)
		return
	}

	waUser, err := h.loadWAUser(ctx, userID, name, email)
	if err != nil || len(waUser.credentials) == 0 {
		http.Error(w, "No passkey found for that email", http.StatusBadRequest)
		return
	}

	options, sessionData, err := h.webAuthn.BeginLogin(waUser)
	if err != nil {
		http.Error(w, "WebAuthn error", http.StatusInternalServerError)
		return
	}

	sessionJSON, _ := json.Marshal(sessionData)
	expiresAt := time.Now().UTC().Add(5 * time.Minute).Format("2006-01-02 15:04:05")
	h.db.ExecContext(ctx,
		`INSERT INTO webauthn_login_sessions (id, user_id, session_data, expires_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT (user_id) DO UPDATE SET session_data = excluded.session_data, expires_at = excluded.expires_at`,
		uuid.NewString(), userID, string(sessionJSON), expiresAt,
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func (h *Handler) finishLogin(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	ctx := r.Context()

	var userID, name string
	h.db.QueryRowContext(ctx,
		`SELECT id, COALESCE(display_name, username) FROM users WHERE username = ? AND is_banned = 0`,
		email,
	).Scan(&userID, &name)

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	var sessionJSONStr string
	err := h.db.QueryRowContext(ctx,
		`DELETE FROM webauthn_login_sessions WHERE user_id = ? AND expires_at > ? RETURNING session_data`,
		userID, now,
	).Scan(&sessionJSONStr)
	if err != nil {
		http.Error(w, "Login session expired", http.StatusBadRequest)
		return
	}

	var sessionData webauthn.SessionData
	json.Unmarshal([]byte(sessionJSONStr), &sessionData)

	waUser, _ := h.loadWAUser(ctx, userID, name, email)
	credential, err := h.webAuthn.FinishLogin(waUser, sessionData, r)
	if err != nil {
		fmt.Printf("webauthn FinishLogin error: %v\n", err)
		http.Error(w, "Passkey verification failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	h.db.ExecContext(ctx,
		`UPDATE webauthn_credentials SET sign_count = ?, last_used_at = datetime('now')
		 WHERE user_id = ? AND credential_id = ?`,
		credential.Authenticator.SignCount, userID, credential.ID,
	)

	if err := CreateSession(ctx, h.db, w, r, userID, h.isProd); err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"redirect": "/"})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	DeleteSession(r.Context(), h.db, w, r)
	http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
}

func (h *Handler) loadWAUser(ctx context.Context, userID, name, email string) (*waUser, error) {
	rows, err := h.db.QueryContext(ctx,
		`SELECT credential_id, public_key, sign_count, backup_eligible, backup_state
		 FROM webauthn_credentials WHERE user_id = ?`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	u := &waUser{id: userID, name: email, displayName: name, email: email}
	for rows.Next() {
		var credID, pubKeyJSON []byte
		var signCount uint32
		var backupEligible, backupState bool
		rows.Scan(&credID, &pubKeyJSON, &signCount, &backupEligible, &backupState)

		var pubKey []byte
		json.Unmarshal(pubKeyJSON, &pubKey)

		u.credentials = append(u.credentials, webauthn.Credential{
			ID:        credID,
			PublicKey: pubKey,
			Flags: webauthn.CredentialFlags{
				BackupEligible: backupEligible,
				BackupState:    backupState,
			},
			Authenticator: webauthn.Authenticator{
				SignCount: signCount,
			},
		})
	}
	return u, nil
}

type waUser struct {
	id          string
	name        string
	displayName string
	email       string
	credentials []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// publicPage renders a minimal public (unauthenticated) page.
func publicPage(title, body string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>%s — FrejaID Demo</title>
  <link rel="stylesheet" href="/static/css/site.css">
</head>
<body>
<header class="site-header">
  <div class="site-header__inner">
    <a href="/auth/login" class="site-logo">FrejaID Demo</a>
  </div>
</header>
<main class="site-main">
<h2>%s</h2>
%s
</main>
<footer class="site-footer"><p>FrejaID Demo</p></footer>
</body></html>`, title, title, body)
}

// Ensure time is imported
var _ = time.Now

const requestFormHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Request Access — FrejaID Demo</title>
  <link rel="stylesheet" href="/static/css/site.css">
</head>
<body>
<header class="site-header">
  <div class="site-header__inner">
    <a href="/auth/login" class="site-logo">FrejaID Demo</a>
  </div>
</header>
<main class="site-main">
<h2>Request Access</h2>
<form class="form" method="POST" action="/auth/request">
  <label>Your name<input type="text" name="name" required></label>
  <label>Email address<input type="email" name="email" required></label>
  <button type="submit">Request Access</button>
</form>
</main>
<footer class="site-footer"><p>FrejaID Demo</p></footer>
</body></html>`

const chooseMethodHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Choose login method — FrejaID Demo</title>
  <link rel="stylesheet" href="/static/css/site.css">
</head>
<body>
<header class="site-header">
  <div class="site-header__inner">
    <a href="/auth/login" class="site-logo">FrejaID Demo</a>
  </div>
</header>
<main class="site-main">
  <h2>Welcome, %s!</h2>
  <p>Your email <strong>%s</strong> has been verified. Choose how you want to log in:</p>
  <div class="auth-choice">
    <div class="auth-choice__option">
      <h3>Passkey</h3>
      <p>Use Face ID, Touch ID, or a security key. Works on this device without a password.</p>
      <a href="/auth/register?token=%s" class="btn">Set up a passkey</a>
    </div>
    <div class="auth-choice__divider">or</div>
    <div class="auth-choice__option">
      <h3>Freja eID</h3>
      <p>Authenticate with your Swedish Freja eID app. No device credential needed.</p>
      <a href="/auth/freja/register?token=%s" class="btn">Continue with Freja eID</a>
    </div>
  </div>
</main>
<footer class="site-footer"><p>FrejaID Demo</p></footer>
</body></html>`

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Log in — FrejaID Demo</title>
  <link rel="stylesheet" href="/static/css/site.css">
</head>
<body>
<header class="site-header">
  <div class="site-header__inner">
    <a href="/auth/login" class="site-logo">FrejaID Demo</a>
  </div>
</header>
<main class="site-main">
<h2>Log in</h2>
<div class="auth-choice">
  <div class="auth-choice__option">
    <h3>Passkey</h3>
    <form class="form" id="loginForm">
      <label>Email address<input type="email" id="email" name="email" required></label>
      <button type="submit">Log in with passkey</button>
    </form>
  </div>
  <div class="auth-choice__divider">or</div>
  <div class="auth-choice__option">
    <h3>Freja eID</h3>
    <p>Log in with your Swedish Freja eID app.</p>
    <a href="/auth/freja/login" class="btn">Log in with Freja eID</a>
  </div>
</div>
<p><a href="/auth/request">Request an account</a></p>
<script>
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value;

  const beginResp = await fetch('/auth/login/begin', {
    method: 'POST',
    body: new URLSearchParams({email}),
  });
  if (!beginResp.ok) { alert(await beginResp.text()); return; }

  const options = await beginResp.json();
  options.publicKey.challenge = base64ToBuffer(options.publicKey.challenge);
  if (options.publicKey.allowCredentials) {
    options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(c => ({
      ...c, id: base64ToBuffer(c.id)
    }));
  }

  const assertion = await navigator.credentials.get(options);
  const finishResp = await fetch('/auth/login/finish?email=' + encodeURIComponent(email), {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      id: assertion.id,
      rawId: bufferToBase64(assertion.rawId),
      type: assertion.type,
      response: {
        authenticatorData: bufferToBase64(assertion.response.authenticatorData),
        clientDataJSON: bufferToBase64(assertion.response.clientDataJSON),
        signature: bufferToBase64(assertion.response.signature),
        userHandle: assertion.response.userHandle ? bufferToBase64(assertion.response.userHandle) : null,
      },
    }),
  });
  if (!finishResp.ok) { alert(await finishResp.text()); return; }
  const {redirect} = await finishResp.json();
  window.location.href = redirect;
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

var registerPasskeyHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Set up passkey — FrejaID Demo</title>
  <link rel="stylesheet" href="/static/css/site.css">
</head>
<body>
<header class="site-header">
  <div class="site-header__inner">
    <a href="/auth/login" class="site-logo">FrejaID Demo</a>
  </div>
</header>
<main class="site-main">
<h2>Welcome, %s!</h2>
<p>Set up your passkey. You can use Face ID, Touch ID, or a security key.</p>
<button id="registerBtn">Set up passkey</button>
<script>
const token = %q;
document.getElementById('registerBtn').addEventListener('click', async () => {
  const beginResp = await fetch('/auth/register/begin?token=' + token, {method: 'POST'});
  if (!beginResp.ok) { alert(await beginResp.text()); return; }

  const options = await beginResp.json();
  options.publicKey.challenge = base64ToBuffer(options.publicKey.challenge);
  options.publicKey.user.id = base64ToBuffer(options.publicKey.user.id);

  const credential = await navigator.credentials.create(options);
  const finishResp = await fetch('/auth/register/finish?token=' + token, {
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
    window.location.href = '/auth/pending';
  } else {
    alert(await finishResp.text());
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

const verifyEmailHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Verify your email — FrejaID Demo</title>
  <link rel="stylesheet" href="/static/css/site.css">
</head>
<body>
<header class="site-header">
  <div class="site-header__inner">
    <a href="/auth/login" class="site-logo">FrejaID Demo</a>
  </div>
</header>
<main class="site-main">
  <h2>Verify your email</h2>
  <p>Click the button below to confirm your email address and continue setting up your account.</p>
  <form method="POST" action="/auth/verify-email">
    <input type="hidden" name="token" value="%s">
    <button type="submit">Verify my email</button>
  </form>
</main>
<footer class="site-footer"><p>FrejaID Demo</p></footer>
</body></html>`
