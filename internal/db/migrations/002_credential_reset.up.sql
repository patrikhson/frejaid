-- Migration 002: credential reset requests.
--
-- Users who have lost access to their passkey or Freja eID can ask an admin
-- to issue a new setup link.  This table tracks those requests through their
-- lifecycle: pending → approved (token issued) → completed.
--
-- Flow:
--   1. User visits the "account already exists" page and submits the form at
--      POST /auth/request-credential-reset.  Row created with status='pending'.
--   2. Admin sees the request in the /admin/credential-resets panel.
--   3. Admin clicks Approve.  setup_token is generated (32 random hex chars);
--      token_expires_at is set to 48 hours from now; status='approved'.
--      An email is sent to the user with a link containing the token.
--   4a. Passkey reset: user visits GET /auth/reset-passkey?token=…
--       Browser calls BeginRegistration → FinishRegistration (same WebAuthn
--       flow as initial registration).  A new webauthn_credentials row is added;
--       status='completed'.
--   4b. Freja reset: user visits GET /auth/reset-freja?token=…
--       Apache does OIDC; Go verifies the Freja email matches the account email;
--       user_identities row upserted; status='completed'.
--
--   provider    — Which credential is being reset: 'passkey' or 'freja'.
--   setup_token — Securely random token emailed to the user after approval.
--                 NULL while status='pending'.
--   token_expires_at — 48-hour window; after this the token is rejected.

CREATE TABLE credential_reset_requests (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider         TEXT NOT NULL DEFAULT 'passkey' CHECK(provider IN ('passkey','freja')),
    setup_token      TEXT UNIQUE,
    token_expires_at TEXT,
    status           TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','completed','rejected')),
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_cred_reset_user_id ON credential_reset_requests(user_id);
CREATE INDEX idx_cred_reset_status  ON credential_reset_requests(status);
