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

CREATE TABLE registration_requests (
    id                       TEXT PRIMARY KEY,
    token                    TEXT NOT NULL UNIQUE,
    name                     TEXT NOT NULL,
    email                    TEXT NOT NULL UNIQUE,
    email_verified           INTEGER NOT NULL DEFAULT 0,
    email_verified_at        TEXT,
    status                   TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','completed')),
    passkey_token            TEXT UNIQUE,
    passkey_token_expires_at TEXT,
    webauthn_session         TEXT,
    pending_credential       TEXT,
    pending_user_id          TEXT UNIQUE,
    passkey_registered_at    TEXT,
    provider                 TEXT NOT NULL DEFAULT 'passkey',
    freja_sub                TEXT,
    user_id                  TEXT REFERENCES users(id),
    expires_at               TEXT NOT NULL,
    created_at               TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_reg_requests_email  ON registration_requests(email);
CREATE INDEX idx_reg_requests_token  ON registration_requests(token);
CREATE INDEX idx_reg_requests_status ON registration_requests(status);

CREATE TABLE webauthn_login_sessions (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    session_data TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE webauthn_add_sessions (
    user_id      TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    session_data TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE freja_link_confirmations (
    token       TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    freja_sub   TEXT NOT NULL,
    freja_email TEXT NOT NULL,
    freja_name  TEXT,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE freja_merge_confirmations (
    token            TEXT PRIMARY KEY,
    existing_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    freja_sub        TEXT NOT NULL,
    freja_email      TEXT NOT NULL,
    freja_name       TEXT,
    expires_at       TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE email_change_tokens (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    new_email  TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
