-- Migration 003: drop an orphaned table and rename confusing columns.
--
-- The original schema used "passkey_token" and "passkey_registered_at" even for
-- the Freja eID path, which is misleading.  This migration gives every column
-- a name that describes what it actually stores, regardless of auth method.
--
-- SQLite RENAME COLUMN requires SQLite ≥ 3.25.0 (released 2018-09-15).
-- The modernc.org/sqlite driver bundles a recent SQLite, so this is safe.

-- freja_merge_confirmations was used by an early "merge account on Freja login"
-- flow.  That flow was replaced by the settings-based link flow at
-- GET /auth/freja/link, so the table is orphaned and can be removed.
DROP TABLE IF EXISTS freja_merge_confirmations;

-- registration_requests column renames for clarity.
--
-- Old name                 → New name                  Why
-- -----------------------------------------------------------------------
-- token                   → email_token               it is the token embedded
--                                                      in the *email* verification
--                                                      link, not a generic token
-- passkey_token           → setup_token               this token gates the "choose
--                                                      your auth method" page for
--                                                      BOTH passkey AND Freja paths
-- passkey_token_expires_at→ setup_token_expires_at    matching rename
-- webauthn_session        → webauthn_challenge         stores the serialised
--                                                      WebAuthn SessionData
--                                                      (challenge + options)
--                                                      between Begin and Finish
-- pending_credential      → credential_data           the serialised credential
--                                                      awaiting admin approval
-- passkey_registered_at   → credential_submitted_at   set for Freja registrations
--                                                      too, not just passkeys

ALTER TABLE registration_requests RENAME COLUMN token                   TO email_token;
ALTER TABLE registration_requests RENAME COLUMN passkey_token           TO setup_token;
ALTER TABLE registration_requests RENAME COLUMN passkey_token_expires_at TO setup_token_expires_at;
ALTER TABLE registration_requests RENAME COLUMN webauthn_session        TO webauthn_challenge;
ALTER TABLE registration_requests RENAME COLUMN pending_credential      TO credential_data;
ALTER TABLE registration_requests RENAME COLUMN passkey_registered_at  TO credential_submitted_at;
