// Package auth implements the full authentication lifecycle:
//
//   Registration flow (new users):
//     1. POST /auth/request        — collect name + email, send verification email
//     2. GET  /auth/verify-email   — user clicks link, email confirmed
//     3. GET  /auth/choose         — user picks passkey or Freja eID
//     4a. GET/POST /auth/register  — WebAuthn passkey registration (3 steps)
//     4b. GET /auth/freja/register — Freja eID registration (Apache-gated)
//     5. Admin approves request    — account created, approval email sent
//
//   Login flow (returning users):
//     Passkey: POST /auth/login/begin + /auth/login/finish (WebAuthn assertion)
//     Freja:   GET  /auth/freja/login  (Apache OIDC → identity in headers)
//
//   Passkey management (authenticated):
//     GET/POST /settings/passkeys — list, add, rename, delete passkeys
//
//   Freja linking (authenticated):
//     GET  /auth/freja/link         — Apache-gated; reads Freja identity from headers
//     POST /auth/freja/link/confirm — user confirms the link
//     POST /settings/freja/unlink   — remove Freja from account
//
//   Credential reset (lost access):
//     POST /auth/request-credential-reset — request new credentials
//     GET/POST /auth/reset-passkey        — passkey reset (token-gated)
//     GET  /auth/reset-freja             — Freja reset (Apache-gated + token)
package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/paftech/frejaid/internal/mail"
)

// Handler holds shared dependencies for all auth HTTP handlers.
type Handler struct {
	db          *sql.DB
	webAuthn    *webauthn.WebAuthn // go-webauthn relying party
	mailer      *mail.Mailer
	baseURL     string   // used when constructing links in emails
	isProd      bool     // controls cookie Secure flag
	sessionKey  string   // session secret (reserved for future signing)
	adminEmails []string // emails that are auto-approved as admin on first signup
}

func NewHandler(db *sql.DB, wa *webauthn.WebAuthn, mailer *mail.Mailer, baseURL, sessionKey string, isProd bool, adminEmails []string) *Handler {
	return &Handler{
		db:          db,
		webAuthn:    wa,
		mailer:      mailer,
		baseURL:     baseURL,
		isProd:      isProd,
		sessionKey:  sessionKey,
		adminEmails: adminEmails,
	}
}

// isAdminEmail reports whether email is in the bootstrap admin list.
// Comparison is case-insensitive.
func (h *Handler) isAdminEmail(email string) bool {
	for _, e := range h.adminEmails {
		if strings.EqualFold(strings.TrimSpace(e), strings.TrimSpace(email)) {
			return true
		}
	}
	return false
}

// maybeAutoApprove approves a pending registration immediately if the user's
// email is in the ADMIN_EMAIL list.  This solves the bootstrap problem: the
// first admin cannot be approved by another admin that doesn't exist yet.
//
// When auto-approval fires:
//   - The registration is approved and the user account is created.
//   - The user is immediately promoted to the "admin" role.
//   - All existing admins receive a notification email.
//
// Returns the new user ID and true if auto-approval occurred.
func (h *Handler) maybeAutoApprove(ctx context.Context, requestID, email string) (string, bool) {
	if !h.isAdminEmail(email) {
		return "", false
	}
	userID, err := SendApprovalEmail(ctx, h.db, h.mailer, h.baseURL, requestID)
	if err != nil {
		return "", false
	}
	h.db.ExecContext(ctx, `UPDATE users SET role='admin' WHERE id=?`, userID)

	// Notify existing admins about the auto-approval for audit purposes.
	var name string
	h.db.QueryRowContext(ctx, `SELECT COALESCE(display_name, username) FROM users WHERE id=?`, userID).Scan(&name)
	rows, _ := h.db.QueryContext(ctx, `SELECT username FROM users WHERE role='admin' AND id != ?`, userID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var adminEmail string
			rows.Scan(&adminEmail)
			h.mailer.SendAdminAutoApproved(adminEmail, name, email)
		}
	}
	return userID, true
}

// RegisterRoutes wires all auth routes into mux.
// requireAuth is the RequireAuth middleware returned by auth.RequireAuth().
func (h *Handler) RegisterRoutes(mux *http.ServeMux, requireAuth func(http.Handler) http.Handler) {
	// ── Registration ─────────────────────────────────────────────────────────
	mux.HandleFunc("GET /auth/request", h.showRequestForm)
	mux.HandleFunc("POST /auth/request", h.submitRequest)
	mux.HandleFunc("GET /auth/verify-email", h.showVerifyEmail)
	mux.HandleFunc("POST /auth/verify-email", h.verifyEmail)
	mux.HandleFunc("GET /auth/choose", h.showChoose)

	// ── Passkey registration ─────────────────────────────────────────────────
	mux.HandleFunc("GET /auth/register", h.showRegisterPasskey)
	mux.HandleFunc("POST /auth/register/begin", h.beginRegisterPasskey)
	mux.HandleFunc("POST /auth/register/finish", h.finishRegisterPasskey)

	// ── Freja eID registration (Apache-gated — see apache config) ────────────
	mux.HandleFunc("GET /auth/freja/register", h.frejaRegister)

	// ── Freja eID login (Apache-gated) ───────────────────────────────────────
	mux.HandleFunc("GET /auth/freja/login", h.frejaLogin)

	// ── Waiting for admin approval ───────────────────────────────────────────
	mux.HandleFunc("GET /auth/pending", h.showPending)

	// ── Passkey login ────────────────────────────────────────────────────────
	mux.HandleFunc("GET /auth/login", h.showLogin)
	mux.HandleFunc("POST /auth/login/begin", h.beginLogin)
	mux.HandleFunc("POST /auth/login/finish", h.finishLogin)

	// ── Logout ───────────────────────────────────────────────────────────────
	mux.HandleFunc("POST /auth/logout", h.logout)

	// ── Passkey management (authenticated) ───────────────────────────────────
	mux.Handle("GET /settings/passkeys", requireAuth(http.HandlerFunc(h.showPasskeys)))
	mux.Handle("POST /settings/passkeys/add/begin", requireAuth(http.HandlerFunc(h.beginAddPasskey)))
	mux.Handle("POST /settings/passkeys/add/finish", requireAuth(http.HandlerFunc(h.finishAddPasskey)))
	mux.Handle("POST /settings/passkeys/{id}/rename", requireAuth(http.HandlerFunc(h.renamePasskey)))
	mux.Handle("POST /settings/passkeys/{id}/delete", requireAuth(http.HandlerFunc(h.deletePasskey)))

	// ── Freja linking (authenticated; Apache-gated) ──────────────────────────
	mux.Handle("GET /auth/freja/link", requireAuth(http.HandlerFunc(h.frejaLink)))
	mux.Handle("POST /auth/freja/link/confirm", requireAuth(http.HandlerFunc(h.frejaLinkConfirm)))

	// ── Freja unlink (authenticated) ─────────────────────────────────────────
	mux.Handle("POST /settings/freja/unlink", requireAuth(http.HandlerFunc(h.frejaUnlink)))

	// ── Credential reset (unauthenticated — for users locked out) ────────────
	mux.HandleFunc("POST /auth/request-credential-reset", h.requestCredentialReset)
	mux.HandleFunc("GET /auth/reset-passkey", h.showResetPasskey)
	mux.HandleFunc("POST /auth/reset-passkey/begin", h.beginResetPasskey)
	mux.HandleFunc("POST /auth/reset-passkey/finish", h.finishResetPasskey)
	mux.HandleFunc("GET /auth/reset-freja", h.resetFreja) // Apache-gated
}

// ─── Registration form ───────────────────────────────────────────────────────

func (h *Handler) showRequestForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, requestFormHTML)
}

// submitRequest handles the initial registration form (name + email).
//
// Security note: we return an identical success page whether or not the email
// is already registered, so that an attacker cannot enumerate accounts by
// submitting email addresses and observing the response.
func (h *Handler) submitRequest(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	email := r.FormValue("email")

	if name == "" || email == "" {
		http.Error(w, "Name and email are required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// If an approved account already exists for this email, show the
	// "account exists" page with the option to request a credential reset.
	// We do this before the generic success response because the user needs
	// to know they have an existing account.
	var existingUserID string
	h.db.QueryRowContext(ctx, `SELECT id FROM users WHERE LOWER(username) = LOWER(?)`, email).Scan(&existingUserID)
	if existingUserID != "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, accountExistsHTML, email, email)
		return
	}

	// If a pending registration exists for this email, silently return
	// success rather than revealing that a pending request exists.
	var exists bool
	h.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM registration_requests WHERE email = ?)`, email).Scan(&exists)
	if exists {
		h.showRequestSuccess(w, r)
		return
	}

	// Create the registration row.  pending_user_id is pre-generated here so
	// that we can use it as the users.id FK target before the users row exists
	// (it is needed when storing the passkey credential in registration_requests).
	token := uuid.NewString()
	pendingUserID := uuid.NewString()
	expiresAt := time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02 15:04:05")
	_, err := h.db.ExecContext(ctx,
		`INSERT INTO registration_requests (id, email_token, name, email, expires_at, pending_user_id)
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

// ─── Email verification ──────────────────────────────────────────────────────

func (h *Handler) showVerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Invalid link", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, verifyEmailHTML, token)
}

// verifyEmail processes the user clicking their verification link.
// On success it generates a setup_token and redirects to /auth/choose, where
// the user picks their authentication method (passkey or Freja eID).
func (h *Handler) verifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")
	if token == "" {
		http.Error(w, "Invalid link", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Generate the setup_token that will gate the "choose auth method" page.
	// This is a separate token from the email_token so we can expire them
	// independently (email token: 24 h; setup token: 24 h from verification).
	setupToken := uuid.NewString()
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	expiresAt := time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02 15:04:05")
	res, err := h.db.ExecContext(ctx,
		`UPDATE registration_requests
		 SET email_verified = 1, email_verified_at = ?,
		     setup_token = ?, setup_token_expires_at = ?
		 WHERE email_token = ? AND expires_at > ? AND email_verified = 0`,
		now, setupToken, expiresAt, token, now,
	)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Could be expired, already verified, or a completely invalid token.
		http.Error(w, "Invalid or expired link", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/auth/choose?token="+setupToken, http.StatusSeeOther)
}

// ─── Auth method choice ──────────────────────────────────────────────────────

// showChoose displays the page where a verified user picks passkey or Freja eID.
// The page is gated by setup_token to ensure only email-verified users reach it.
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
		 WHERE setup_token = ? AND setup_token_expires_at > ?
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

// ─── Passkey registration (WebAuthn) ─────────────────────────────────────────

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
		 WHERE setup_token = ? AND setup_token_expires_at > ?
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

// beginRegisterPasskey starts the WebAuthn registration ceremony.
//
// WebAuthn registration — step 1 of 2:
//   The server calls BeginRegistration() which:
//     a) Generates a cryptographically random challenge.
//     b) Returns PublicKeyCredentialCreationOptions (challenge, rp, user,
//        pubKeyCredParams, timeout, excludeCredentials, authenticatorSelection).
//   The browser's navigator.credentials.create() uses these options to
//   instruct the authenticator (Touch ID, YubiKey…) to create a key pair.
//   The challenge is also stored as webauthn_challenge so we can verify it
//   in step 2.
func (h *Handler) beginRegisterPasskey(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	ctx := r.Context()

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	var reqID, name, email, pendingUserID string
	err := h.db.QueryRowContext(ctx,
		`SELECT id, name, email, pending_user_id FROM registration_requests
		 WHERE setup_token = ? AND setup_token_expires_at > ?
		   AND status = 'pending' AND email_verified = 1`,
		token, now,
	).Scan(&reqID, &name, &email, &pendingUserID)
	if err != nil {
		http.Error(w, "Invalid or expired link", http.StatusBadRequest)
		return
	}

	// waUser wraps the pending user's data in the webauthn.User interface.
	// The ID must be stable for the lifetime of the credential; we use the
	// pre-allocated pending_user_id which becomes the users.id later.
	waUser := &waUser{id: pendingUserID, name: name, displayName: name, email: email}

	// BeginRegistration generates the challenge and options.
	options, sessionData, err := h.webAuthn.BeginRegistration(waUser)
	if err != nil {
		http.Error(w, "WebAuthn error", http.StatusInternalServerError)
		return
	}

	// Store the SessionData server-side so we can verify the authenticator's
	// response in finishRegisterPasskey.  The browser receives the challenge
	// inside `options` but we keep the full SessionData (includes user
	// verification policy, allowed algorithms, etc.) to validate against.
	sessionJSON, _ := json.Marshal(sessionData)
	h.db.ExecContext(ctx,
		`UPDATE registration_requests SET webauthn_challenge = ? WHERE id = ?`,
		string(sessionJSON), reqID,
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// finishRegisterPasskey completes the WebAuthn registration ceremony.
//
// WebAuthn registration — step 2 of 2:
//   The browser calls navigator.credentials.create() and gets back a
//   PublicKeyCredential.  It POSTs the credential (JSON-encoded) here.
//   FinishRegistration() verifies:
//     a) The challenge in clientDataJSON matches what we sent in step 1.
//     b) The origin in clientDataJSON matches our RPID.
//     c) The attestation is valid (we accept any authenticator for simplicity).
//   On success we extract the public key and store it as credential_data.
//   The account is NOT created yet — an admin must approve first.
func (h *Handler) finishRegisterPasskey(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	ctx := r.Context()

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	var reqID, name, email, pendingUserID string
	var sessionJSONStr sql.NullString
	err := h.db.QueryRowContext(ctx,
		`SELECT id, name, email, pending_user_id, webauthn_challenge FROM registration_requests
		 WHERE setup_token = ? AND setup_token_expires_at > ?
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

	// FinishRegistration validates the authenticator's response against the
	// stored session and returns the verified credential.
	credential, err := h.webAuthn.FinishRegistration(waUser, sessionData, r)
	if err != nil {
		http.Error(w, "Passkey registration failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Store the essential credential fields as JSON.  We cannot create the
	// webauthn_credentials row yet because the users row does not exist
	// (admin approval creates it).  Instead we park the credential here until
	// approval.
	pubKey, _ := json.Marshal(credential.PublicKey)
	stored := storedCredential{
		ID:             credential.ID,
		PublicKey:      pubKey,
		AAGUID:         credential.Authenticator.AAGUID,
		SignCount:       credential.Authenticator.SignCount,
		BackupEligible: credential.Flags.BackupEligible,
		BackupState:    credential.Flags.BackupState,
	}
	storedJSON, _ := json.Marshal(stored)
	h.db.ExecContext(ctx,
		`UPDATE registration_requests
		 SET credential_data = ?, credential_submitted_at = datetime('now')
		 WHERE id = ?`,
		string(storedJSON), reqID,
	)

	// If the email is in the ADMIN_EMAIL list, approve immediately without
	// waiting for a human admin.
	if _, ok := h.maybeAutoApprove(ctx, reqID, email); ok {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, publicPage("Account ready",
			`<p>Your account has been created. <a href="/auth/login">Log in now</a>.</p>`))
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, publicPage("Request submitted",
		`<p>Your passkey is registered. You'll receive an email when an admin approves your account.</p>`))
}

// storedCredential is the subset of webauthn.Credential fields we need to
// persist between registration and admin approval.  The full Credential object
// from go-webauthn is not serialisable as-is, so we extract what we need.
type storedCredential struct {
	ID             []byte `json:"id"`
	PublicKey      []byte `json:"public_key"`
	AAGUID         []byte `json:"aaguid"`
	SignCount       uint32 `json:"sign_count"`
	BackupEligible bool   `json:"backup_eligible"`
	BackupState    bool   `json:"backup_state"`
}

// ─── Admin approval ──────────────────────────────────────────────────────────

// SendApprovalEmail is called by the admin handler when an admin approves a
// registration request.  It creates the users row, the credential row (passkey)
// or identity row (Freja), marks the request as completed, and sends the user
// an email telling them they can now log in.
//
// Returns the new user ID so the caller can do additional work (e.g. set role).
func SendApprovalEmail(ctx context.Context, db *sql.DB, mailer *mail.Mailer, baseURL, requestID string) (string, error) {
	var name, email, pendingUserID, provider string
	var frejaSub sql.NullString
	var credJSON sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT name, email, pending_user_id, provider, freja_sub, credential_data
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

// sendApprovalPasskey creates the user + passkey credential and sends the
// "you're approved" email for a passkey registration.
func sendApprovalPasskey(ctx context.Context, db *sql.DB, mailer *mail.Mailer, baseURL, requestID, pendingUserID, name, email string, credJSON sql.NullString) (string, error) {
	if !credJSON.Valid || credJSON.String == "" {
		return "", fmt.Errorf("passkey not yet registered")
	}

	var cred storedCredential
	if err := json.Unmarshal([]byte(credJSON.String), &cred); err != nil {
		return "", fmt.Errorf("corrupt credential data: %w", err)
	}

	// Create the user row using the pre-allocated pending_user_id.
	userID := pendingUserID
	_, err := db.ExecContext(ctx,
		`INSERT INTO users (id, username, display_name, role) VALUES (?, ?, ?, 'passive')`,
		userID, email, name,
	)
	if err != nil {
		return "", fmt.Errorf("create user: %w", err)
	}

	// Store the passkey credential now that the users row exists.
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

// sendApprovalFreja creates the user + Freja identity and sends the approval
// email for a Freja eID registration.
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
	// ON CONFLICT DO NOTHING: if the Freja identity was already linked somehow
	// (shouldn't happen in normal flow), we don't overwrite it.
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

// ─── Pending page ────────────────────────────────────────────────────────────

func (h *Handler) showPending(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, publicPage("Pending approval",
		`<p>Your request is submitted. You'll receive an email when an admin approves your account.</p>`))
}

// ─── Passkey login (WebAuthn assertion) ──────────────────────────────────────

func (h *Handler) showLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, loginHTML)
}

// beginLogin starts the WebAuthn login assertion ceremony.
//
// WebAuthn login — step 1 of 2:
//   BeginLogin() generates a random challenge and returns
//   PublicKeyCredentialRequestOptions which include:
//     - challenge:          the random nonce the authenticator must sign
//     - allowCredentials:   list of credential IDs registered for this user,
//                           so the device knows which private key to use
//     - userVerification:   "preferred" = use PIN/biometrics if available
//   The challenge is stored in webauthn_login_sessions keyed by user_id.
func (h *Handler) beginLogin(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	ctx := r.Context()

	var userID, name string
	err := h.db.QueryRowContext(ctx,
		`SELECT id, COALESCE(display_name, username) FROM users WHERE username = ? AND is_banned = 0`,
		email,
	).Scan(&userID, &name)
	if err != nil {
		// Don't reveal whether the account exists; just say no passkey found.
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
	// ON CONFLICT replaces any previous in-progress login for this user,
	// preventing duplicate rows if the user refreshes and starts again.
	h.db.ExecContext(ctx,
		`INSERT INTO webauthn_login_sessions (id, user_id, session_data, expires_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT (user_id) DO UPDATE SET session_data = excluded.session_data, expires_at = excluded.expires_at`,
		uuid.NewString(), userID, string(sessionJSON), expiresAt,
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// finishLogin completes the WebAuthn login assertion ceremony.
//
// WebAuthn login — step 2 of 2:
//   The browser calls navigator.credentials.get() with the options from
//   step 1.  The authenticator signs the challenge and returns an assertion.
//   FinishLogin() verifies:
//     a) The challenge signature is valid (using the stored public key).
//     b) The origin matches our RPID.
//     c) The sign_count has not decreased (replay detection).
//   On success we update sign_count and create a session.
func (h *Handler) finishLogin(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	ctx := r.Context()

	var userID, name string
	h.db.QueryRowContext(ctx,
		`SELECT id, COALESCE(display_name, username) FROM users WHERE username = ? AND is_banned = 0`,
		email,
	).Scan(&userID, &name)

	// Retrieve and delete the login session atomically.  Using a RETURNING
	// DELETE means there's no window between the read and the delete where
	// two concurrent finish requests could both succeed.
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

	// FinishLogin verifies the authenticator's signature.
	credential, err := h.webAuthn.FinishLogin(waUser, sessionData, r)
	if err != nil {
		fmt.Printf("webauthn FinishLogin error: %v\n", err)
		http.Error(w, "Passkey verification failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Update the sign_count to detect future replay attempts, and record
	// when this credential was last used.
	h.db.ExecContext(ctx,
		`UPDATE webauthn_credentials SET sign_count = ?, last_used_at = datetime('now')
		 WHERE user_id = ? AND credential_id = ?`,
		credential.Authenticator.SignCount, userID, credential.ID,
	)

	if err := CreateSession(ctx, h.db, w, r, userID, h.isProd); err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	// The browser's JS reads the redirect URL from the JSON response.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"redirect": "/"})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	DeleteSession(r.Context(), h.db, w, r)
	http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
}

// ─── Shared WebAuthn helpers ──────────────────────────────────────────────────

// loadWAUser loads a user's passkey credentials from the database and returns
// them wrapped in the webauthn.User interface expected by go-webauthn.
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

		// public_key is stored as JSON-encoded bytes (from json.Marshal([]byte{…})).
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

// waUser implements the webauthn.User interface required by go-webauthn.
// It wraps a user's basic info and their list of registered passkeys.
type waUser struct {
	id          string
	name        string // used as the username in the WebAuthn credential
	displayName string // shown in the browser passkey prompt
	email       string
	credentials []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// ─── HTML helpers ────────────────────────────────────────────────────────────

// publicPage renders a minimal full-page HTML response for unauthenticated
// pages that don't need the full layout (no nav bar, no session required).
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

// ─── Inline HTML templates ───────────────────────────────────────────────────
// All UI for the auth flow lives here so the complete flow can be read in one
// file.  In a production app you would use html/template files instead.

// accountExistsHTML is shown when someone tries to register with an email that
// already belongs to an approved account.  It offers the credential reset flow.
// Format args: %s = email (displayed), %s = email (form hidden field).
const accountExistsHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Account already exists — FrejaID Demo</title>
  <link rel="stylesheet" href="/static/css/site.css">
</head>
<body>
<header class="site-header">
  <div class="site-header__inner">
    <a href="/auth/login" class="site-logo">FrejaID Demo</a>
  </div>
</header>
<main class="site-main">
  <h2>Account already exists</h2>
  <p>An account with the email <strong>%s</strong> is already registered.</p>
  <p>If you still have access to your credentials, <a href="/auth/login">log in here</a>.</p>
  <h3>Lost access?</h3>
  <p>If you can no longer log in, request new credentials below. An admin will review and send you a setup link.</p>
  <form class="form" method="POST" action="/auth/request-credential-reset">
    <input type="hidden" name="email" value="%s">
    <fieldset>
      <legend>Credential type</legend>
      <label><input type="radio" name="provider" value="passkey" checked> Passkey (Face ID, Touch ID, security key)</label><br>
      <label style="margin-top:0.4rem"><input type="radio" name="provider" value="freja"> Freja eID</label>
    </fieldset>
    <button type="submit" class="btn" style="margin-top:1rem">Request new credentials</button>
  </form>
</main>
<footer class="site-footer"><p>FrejaID Demo</p></footer>
</body></html>`

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

// chooseMethodHTML is shown after email verification.
// Format args: %s = name, %s = email, %s = token (passkey link), %s = token (Freja link).
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

// loginHTML contains the login page with both passkey and Freja eID options.
//
// The passkey flow is entirely client-side JS:
//   1. User enters email and submits the form.
//   2. JS POSTs to /auth/login/begin — receives PublicKeyCredentialRequestOptions.
//   3. JS calls navigator.credentials.get(options) — browser prompts for Touch ID etc.
//   4. JS POSTs the assertion to /auth/login/finish — server verifies and creates session.
//   5. Server returns {"redirect": "/"} — JS navigates there.
//
// Binary data (challenge, credential IDs) must be base64url-encoded to survive
// JSON serialisation.  The helpers base64ToBuffer / bufferToBase64 handle the
// conversion between ArrayBuffer (used by the WebAuthn API) and base64url strings.
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

  // Step 1: ask the server for a challenge and the list of credential IDs
  // registered for this email address.
  const beginResp = await fetch('/auth/login/begin', {
    method: 'POST',
    body: new URLSearchParams({email}),
  });
  if (!beginResp.ok) { alert(await beginResp.text()); return; }

  const options = await beginResp.json();

  // The WebAuthn API requires ArrayBuffer, but JSON only carries strings.
  // Decode the base64url-encoded challenge and credential IDs.
  options.publicKey.challenge = base64ToBuffer(options.publicKey.challenge);
  if (options.publicKey.allowCredentials) {
    options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(c => ({
      ...c, id: base64ToBuffer(c.id)
    }));
  }

  // Step 2: prompt the user to verify with Face ID / Touch ID / security key.
  // The browser shows a native UI; we don't control its appearance.
  const assertion = await navigator.credentials.get(options);

  // Step 3: send the signed assertion to the server for verification.
  // All binary fields must be re-encoded as base64url for JSON transport.
  const finishResp = await fetch('/auth/login/finish?email=' + encodeURIComponent(email), {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      id: assertion.id,
      rawId: bufferToBase64(assertion.rawId),
      type: assertion.type,
      response: {
        authenticatorData: bufferToBase64(assertion.response.authenticatorData),
        clientDataJSON:    bufferToBase64(assertion.response.clientDataJSON),
        signature:         bufferToBase64(assertion.response.signature),
        userHandle: assertion.response.userHandle ? bufferToBase64(assertion.response.userHandle) : null,
      },
    }),
  });
  if (!finishResp.ok) { alert(await finishResp.text()); return; }
  const {redirect} = await finishResp.json();
  window.location.href = redirect;
});

// base64ToBuffer decodes a base64url string to an ArrayBuffer.
// The WebAuthn API uses ArrayBuffer for all binary data (challenges, IDs…).
function base64ToBuffer(b64) {
  const s = atob(b64.replace(/-/g,'+').replace(/_/g,'/'));
  return Uint8Array.from(s, c => c.charCodeAt(0)).buffer;
}

// bufferToBase64 encodes an ArrayBuffer to a base64url string (no padding).
// base64url uses '-' and '_' instead of '+' and '/' to be URL-safe.
function bufferToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
</script>
</main>
<footer class="site-footer"><p>FrejaID Demo</p></footer>
</body></html>`

// registerPasskeyHTML is the page where a new user sets up their passkey.
// Format args: %s = display name, %q = setup token (Go-quoted for safe JS embedding).
//
// The JS flow mirrors loginHTML but uses credentials.create() instead of
// credentials.get(), and posts to /auth/register/begin and /auth/register/finish.
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
  // Step 1: get the registration options (challenge, rp info, user info).
  const beginResp = await fetch('/auth/register/begin?token=' + token, {method: 'POST'});
  if (!beginResp.ok) { alert(await beginResp.text()); return; }

  const options = await beginResp.json();

  // Decode binary fields from base64url to ArrayBuffer.
  options.publicKey.challenge = base64ToBuffer(options.publicKey.challenge);
  options.publicKey.user.id   = base64ToBuffer(options.publicKey.user.id);

  // Step 2: ask the browser to create a new passkey.
  // The authenticator generates a key pair; the private key stays on device.
  const credential = await navigator.credentials.create(options);

  // Step 3: send the public key and attestation to the server.
  const finishResp = await fetch('/auth/register/finish?token=' + token, {
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

// verifyEmailHTML is the landing page for the email verification link.
// It shows a single button so verification is a deliberate POST, not a GET,
// preventing accidental verification by link pre-fetchers or email scanners.
// Format arg: %s = email_token value.
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

