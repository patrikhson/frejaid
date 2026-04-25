-- Reverse migration 003.
ALTER TABLE registration_requests RENAME COLUMN email_token             TO token;
ALTER TABLE registration_requests RENAME COLUMN setup_token             TO passkey_token;
ALTER TABLE registration_requests RENAME COLUMN setup_token_expires_at  TO passkey_token_expires_at;
ALTER TABLE registration_requests RENAME COLUMN webauthn_challenge      TO webauthn_session;
ALTER TABLE registration_requests RENAME COLUMN credential_data         TO pending_credential;
ALTER TABLE registration_requests RENAME COLUMN credential_submitted_at TO passkey_registered_at;

CREATE TABLE freja_merge_confirmations (
    token            TEXT PRIMARY KEY,
    existing_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    freja_sub        TEXT NOT NULL,
    freja_email      TEXT NOT NULL,
    freja_name       TEXT,
    expires_at       TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
