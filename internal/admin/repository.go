// Database helpers for the admin package.
// Keeping queries here instead of inline in handler.go makes them easier to
// read, test, and reuse across handlers.
package admin

import (
	"context"
	"database/sql"
	"time"
)

// ─── Dashboard counts ─────────────────────────────────────────────────────────

// Counts holds the pending-item numbers shown on the admin dashboard.
type Counts struct {
	PendingRegistrations    int
	PendingCredentialResets int
}

// GetCounts returns the number of items pending admin review.
// A registration is "ready" when the user has verified their email AND
// submitted a credential (passkey credential_data stored, or Freja sub recorded).
func GetCounts(ctx context.Context, db *sql.DB) Counts {
	var c Counts
	db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM registration_requests
		 WHERE status='pending' AND email_verified=1
		   AND (credential_data IS NOT NULL OR (provider='freja' AND credential_submitted_at IS NOT NULL))`,
	).Scan(&c.PendingRegistrations)
	db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM credential_reset_requests WHERE status='pending'`,
	).Scan(&c.PendingCredentialResets)
	return c
}

// ─── Registrations ────────────────────────────────────────────────────────────

// RegistrationRequest is a read model for the registrations admin list.
type RegistrationRequest struct {
	ID        string
	Name      string
	Email     string
	Provider  string    // "passkey" or "freja"
	CreatedAt time.Time
}

// ListPendingRegistrations returns all registrations waiting for admin approval.
// Only rows where the user has completed their credential setup are returned.
func ListPendingRegistrations(ctx context.Context, db *sql.DB) ([]RegistrationRequest, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, email, provider, created_at
		 FROM registration_requests
		 WHERE status='pending' AND email_verified=1
		   AND (credential_data IS NOT NULL OR (provider='freja' AND credential_submitted_at IS NOT NULL))
		 ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reqs []RegistrationRequest
	for rows.Next() {
		var rq RegistrationRequest
		var createdAtStr string
		rows.Scan(&rq.ID, &rq.Name, &rq.Email, &rq.Provider, &createdAtStr)
		rq.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
		reqs = append(reqs, rq)
	}
	return reqs, nil
}

// RejectRegistration marks a registration request as rejected.
// The AND status='pending' guard prevents double-rejecting an already-processed row.
func RejectRegistration(ctx context.Context, db *sql.DB, requestID string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE registration_requests SET status='rejected' WHERE id=? AND status='pending'`,
		requestID)
	return err
}

// ─── Users ────────────────────────────────────────────────────────────────────

// User is a read model for the users admin list.
type User struct {
	ID          string
	Username    string // email address
	DisplayName string
	Role        string   // "passive", "active", or "admin"
	IsBanned    bool
	CreatedAt   time.Time
}

// ListUsers returns all users ordered by creation date (newest first).
func ListUsers(ctx context.Context, db *sql.DB) ([]User, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, username, COALESCE(display_name, username), role, is_banned, created_at
		 FROM users ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		var createdAtStr string
		var isBanned int // SQLite stores booleans as 0/1
		rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &isBanned, &createdAtStr)
		u.IsBanned = isBanned != 0
		u.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
		users = append(users, u)
	}
	return users, nil
}

// SetUserBan sets or clears the is_banned flag.
// Banned users are rejected on every request (checked in GetSession).
func SetUserBan(ctx context.Context, db *sql.DB, userID string, banned bool) error {
	b := 0
	if banned {
		b = 1
	}
	_, err := db.ExecContext(ctx, `UPDATE users SET is_banned=? WHERE id=?`, b, userID)
	return err
}

// SetUserRole updates a user's role.
// The caller is responsible for validating that role is one of the allowed values.
func SetUserRole(ctx context.Context, db *sql.DB, userID, role string) error {
	_, err := db.ExecContext(ctx, `UPDATE users SET role=? WHERE id=?`, role, userID)
	return err
}

// ─── Credential resets ────────────────────────────────────────────────────────

// CredentialResetRequest is a read model for the credential resets admin list.
type CredentialResetRequest struct {
	ID        string
	UserName  string // display name or email
	UserEmail string
	Provider  string    // "passkey" or "freja"
	CreatedAt time.Time
}

// ListPendingCredentialResets returns all credential reset requests awaiting
// admin review, in chronological order.
func ListPendingCredentialResets(ctx context.Context, db *sql.DB) ([]CredentialResetRequest, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT cr.id, COALESCE(u.display_name, u.username), u.username, cr.provider, cr.created_at
		 FROM credential_reset_requests cr
		 JOIN users u ON u.id = cr.user_id
		 WHERE cr.status = 'pending'
		 ORDER BY cr.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reqs []CredentialResetRequest
	for rows.Next() {
		var rq CredentialResetRequest
		var createdAtStr string
		rows.Scan(&rq.ID, &rq.UserName, &rq.UserEmail, &rq.Provider, &createdAtStr)
		rq.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
		reqs = append(reqs, rq)
	}
	return reqs, nil
}

// ApproveCredentialReset marks a request as approved and stores the setup token.
// The AND status='pending' guard prevents approving an already-processed row.
func ApproveCredentialReset(ctx context.Context, db *sql.DB, id, token, expiresAt string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE credential_reset_requests
		 SET status='approved', setup_token=?, token_expires_at=?
		 WHERE id=? AND status='pending'`,
		token, expiresAt, id)
	return err
}

// RejectCredentialReset marks a credential reset request as rejected.
func RejectCredentialReset(ctx context.Context, db *sql.DB, id string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE credential_reset_requests SET status='rejected' WHERE id=? AND status='pending'`,
		id)
	return err
}
