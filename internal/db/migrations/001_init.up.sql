-- FrejaID Demo — initial database schema.
--
-- Note: column names in registration_requests were improved in migration 003.
-- Read that file first if you want to understand the final column names.
--
-- Design notes
-- ────────────
-- • All primary keys are UUIDs stored as TEXT.  This avoids auto-increment
--   races and keeps IDs opaque to users.
-- • Timestamps are TEXT in ISO format "2006-01-02 15:04:05" (UTC).
--   SQLite has no native DATETIME type; text columns work with the built-in
--   datetime() function and are easy to compare with string ordering.
-- • Foreign keys are enabled at connection time — see db.go.
-- • ON DELETE CASCADE means deleting a user automatically removes every row
--   that depends on them (sessions, credentials, pending data).

-- ─────────────────────────────────────────────────────────────────────────────
-- users
--
-- Created when an admin approves a registration request — not at signup time.
-- This means every row in this table is an approved, non-pending user.
--
--   username     — The user's email address, used as the login identifier.
--                  Treated as case-insensitive (always LOWER() before comparing).
--   display_name — Optional friendly name shown in the UI; falls back to username.
--   role         — Controls access level:
--                    passive — can log in, no special permissions (default)
--                    active  — reserved for future use (e.g. content authors)
--                    admin   — can access the /admin panel
--   is_banned    — Banned users are rejected on every request, including
--                  requests with an existing valid session cookie.
--   invited_by   — Self-referential FK; NULL for self-registered users.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE users (
    id           TEXT PRIMARY KEY,
    username     TEXT NOT NULL UNIQUE,
    display_name TEXT,
    role         TEXT NOT NULL DEFAULT 'passive' CHECK(role IN ('passive','active','admin')),
    is_banned    INTEGER NOT NULL DEFAULT 0,
    invited_by   TEXT REFERENCES users(id),
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_users_username ON users(username);

-- ─────────────────────────────────────────────────────────────────────────────
-- sessions
--
-- Server-side session store.  The browser only holds the session ID in a
-- HttpOnly cookie.  Storing sessions server-side lets us invalidate them
-- instantly (e.g. when banning a user) without waiting for a cookie to expire.
--
--   ip_address   — Logged for audit purposes; not used for session validation.
--   user_agent   — Same.
--   last_seen_at — Updated on every authenticated request (background write).
--   expires_at   — Compared against datetime('now') on every lookup.
--                  Expired rows are cleaned up hourly by CleanupSessions().
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address   TEXT,
    user_agent   TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at   TEXT NOT NULL
);

CREATE INDEX idx_sessions_user_id    ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- ─────────────────────────────────────────────────────────────────────────────
-- user_identities
--
-- External identity providers linked to a user account.  Currently only the
-- "freja" provider is used, but the table is intentionally generic.
--
--   provider         — Provider name, e.g. "freja".
--   provider_subject — Stable opaque identifier from the provider (the "sub"
--                      claim in OIDC).  More reliable than email because email
--                      addresses can change while the subject stays constant.
--   provider_email   — The email the provider currently reports.  Kept for
--                      display and as a fallback lookup when the sub is unknown.
--
-- UNIQUE (provider, provider_subject): one Freja account per user.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE user_identities (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider         TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    provider_email   TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (provider, provider_subject)
);

CREATE INDEX idx_user_identities_user_id        ON user_identities(user_id);
CREATE INDEX idx_user_identities_provider_email ON user_identities(provider, provider_email);

-- ─────────────────────────────────────────────────────────────────────────────
-- webauthn_credentials
--
-- Registered passkeys.  A user may have many (one per device or security key).
--
-- How WebAuthn / FIDO2 passkeys work:
--
--   Registration:
--     1. Server sends a random challenge and options to the browser.
--     2. The authenticator (Face ID, Touch ID, YubiKey…) generates an
--        asymmetric key pair.  The PRIVATE key never leaves the device.
--     3. The authenticator returns the PUBLIC key and a credential_id.
--     4. We store both here.
--
--   Login:
--     1. Server sends a new random challenge.
--     2. The authenticator signs the challenge with its stored private key,
--        using the credential_id to find the right key.
--     3. We verify the signature against the stored public_key.
--     4. No password, no secret transmitted over the wire.
--
-- Key columns:
--   credential_id   — Opaque byte handle the authenticator uses to look up its
--                     private key.  Sent to the browser in BeginLogin so the
--                     device knows which key to use.
--   public_key      — CBOR-encoded public key bytes (stored as JSON by the
--                     go-webauthn library for portability).
--   aaguid          — Authenticator Attestation GUID: identifies the authenticator
--                     model (e.g. the GUID for "YubiKey 5 NFC").  Can be used to
--                     enforce hardware-key-only policies.
--   sign_count      — Counter the authenticator increments on every use.
--                     A sign_count lower than the stored value can indicate a
--                     cloned credential (replay attack).
--   backup_eligible — True if the private key can be synced to iCloud Keychain,
--                     Google Password Manager, etc.
--   backup_state    — True if the key is currently synced/backed up.
--   name            — Human-friendly label the user can edit ("MacBook", "YubiKey").
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE webauthn_credentials (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   BLOB NOT NULL UNIQUE,
    public_key      BLOB NOT NULL,
    aaguid          BLOB,
    sign_count      INTEGER NOT NULL DEFAULT 0,
    backup_eligible INTEGER NOT NULL DEFAULT 0,
    backup_state    INTEGER NOT NULL DEFAULT 0,
    name            TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at    TEXT
);

CREATE INDEX idx_webauthn_creds_user_id ON webauthn_credentials(user_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- registration_requests
--
-- Tracks every step of a new-user signup from initial form submission through
-- admin approval.  One row per unique email address.
--
-- Full lifecycle (see also handler.go for the Go side):
--
--   Step 1 — User submits name + email at POST /auth/request.
--             Row created; email_token generated; verification email sent.
--
--   Step 2 — User clicks the link in the email (GET /auth/verify-email).
--             email_verified set to 1; setup_token generated; user redirected
--             to /auth/choose to pick their auth method.
--             (Column names updated in migration 003.)
--
--   Step 3a — Passkey path: browser calls Begin/FinishRegistration.
--             webauthn_challenge holds the WebAuthn session between the two
--             requests; credential_data holds the serialised credential once
--             complete; credential_submitted_at is set.
--
--   Step 3b — Freja path: Apache does OIDC → sets provider='freja', freja_sub;
--             credential_submitted_at is set.
--
--   Step 4 — Admin reviews the row, clicks Approve.
--             users + webauthn_credentials/user_identities rows created;
--             status set to 'completed'.
--
-- Notable columns:
--   pending_user_id — UUID pre-generated for the future users.id.  This lets us
--                     reference the eventual user before the users row exists.
--   webauthn_challenge — Serialised WebAuthn SessionData kept between the Begin
--                        and Finish registration HTTP calls.
--   credential_data — JSON blob of the credential awaiting admin approval.
--   freja_sub       — The Freja OIDC "sub" claim, received via Apache headers.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE registration_requests (
    id                       TEXT PRIMARY KEY,
    token                    TEXT NOT NULL UNIQUE,   -- renamed email_token in migration 003
    name                     TEXT NOT NULL,
    email                    TEXT NOT NULL UNIQUE,
    email_verified           INTEGER NOT NULL DEFAULT 0,
    email_verified_at        TEXT,
    status                   TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','completed')),
    passkey_token            TEXT UNIQUE,            -- renamed setup_token in migration 003
    passkey_token_expires_at TEXT,                   -- renamed setup_token_expires_at in migration 003
    webauthn_session         TEXT,                   -- renamed webauthn_challenge in migration 003
    pending_credential       TEXT,                   -- renamed credential_data in migration 003
    pending_user_id          TEXT UNIQUE,
    passkey_registered_at    TEXT,                   -- renamed credential_submitted_at in migration 003
    provider                 TEXT NOT NULL DEFAULT 'passkey',
    freja_sub                TEXT,
    user_id                  TEXT REFERENCES users(id),
    expires_at               TEXT NOT NULL,
    created_at               TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_reg_requests_email  ON registration_requests(email);
CREATE INDEX idx_reg_requests_token  ON registration_requests(token);
CREATE INDEX idx_reg_requests_status ON registration_requests(status);

-- ─────────────────────────────────────────────────────────────────────────────
-- webauthn_login_sessions
--
-- Short-lived (5 minutes) store for WebAuthn challenge state during login.
--
-- Why this table exists:
--   POST /auth/login/begin  — calls webAuthn.BeginLogin(), which returns a
--                             challenge and a SessionData object.  Both are sent
--                             to the browser; the SessionData must be kept
--                             server-side so FinishLogin can verify the response.
--   POST /auth/login/finish — retrieves and deletes the row, then calls
--                             webAuthn.FinishLogin() with the stored SessionData
--                             and the browser's signed response.
--
-- UNIQUE on user_id: only one concurrent login attempt per user at a time.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE webauthn_login_sessions (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    session_data TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─────────────────────────────────────────────────────────────────────────────
-- webauthn_add_sessions
--
-- Same pattern as webauthn_login_sessions but for adding a second passkey
-- from the settings page or during a credential reset.
-- user_id is the primary key because at most one "add passkey" flow can be
-- in progress per user at a time.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE webauthn_add_sessions (
    user_id      TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    session_data TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─────────────────────────────────────────────────────────────────────────────
-- freja_link_confirmations
--
-- Short-lived (10 minutes) token that bridges the Freja OIDC redirect back to
-- the authenticated user's session when linking Freja to an existing account.
--
-- Flow (see also freja.go):
--   1. Logged-in user clicks "Link Freja eID" → browser goes to
--      GET /auth/freja/link (an Apache-protected path).
--   2. Apache performs OIDC authentication with Freja; on success it sets
--      X-Remote-User, X-Freja-Sub, X-Freja-Name headers and proxies the
--      request to the Go app.
--   3. Go reads the Freja identity from the headers, stores it here, and
--      shows a confirmation page with the token.
--   4. User submits the confirmation form → POST /auth/freja/link/confirm.
--   5. Go deletes this row, writes to user_identities, redirects to settings.
--
-- The confirmation step (4) is needed because the OIDC redirect and the
-- user's existing session arrive via different requests.  The token ties them.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE freja_link_confirmations (
    token       TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    freja_sub   TEXT NOT NULL,
    freja_email TEXT NOT NULL,
    freja_name  TEXT,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─────────────────────────────────────────────────────────────────────────────
-- freja_merge_confirmations (DROPPED in migration 003)
--
-- Was used by an early flow that merged a Freja identity into an existing
-- account when the user logged in with Freja.  Replaced by the settings-based
-- link flow above.  Kept here for schema history; see migration 003.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE freja_merge_confirmations (
    token            TEXT PRIMARY KEY,
    existing_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    freja_sub        TEXT NOT NULL,
    freja_email      TEXT NOT NULL,
    freja_name       TEXT,
    expires_at       TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─────────────────────────────────────────────────────────────────────────────
-- email_change_tokens
--
-- Short-lived (24 hours) tokens for email address changes.
-- The user submits a new address; we email a confirmation link to that new
-- address.  Only after clicking the link is the change applied.
-- This prevents someone from locking a user out by changing their email.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE email_change_tokens (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    new_email  TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
