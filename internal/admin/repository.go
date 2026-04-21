package admin

import (
	"context"
	"database/sql"
	"time"
)

type Counts struct {
	PendingRegistrations int
}

func GetCounts(ctx context.Context, db *sql.DB) Counts {
	var c Counts
	db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM registration_requests
		 WHERE status='pending' AND email_verified=1
		   AND (pending_credential IS NOT NULL OR (provider='freja' AND passkey_registered_at IS NOT NULL))`,
	).Scan(&c.PendingRegistrations)
	return c
}

type RegistrationRequest struct {
	ID        string
	Name      string
	Email     string
	Provider  string
	CreatedAt time.Time
}

func ListPendingRegistrations(ctx context.Context, db *sql.DB) ([]RegistrationRequest, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, email, provider, created_at
		 FROM registration_requests
		 WHERE status='pending' AND email_verified=1
		   AND (pending_credential IS NOT NULL OR (provider='freja' AND passkey_registered_at IS NOT NULL))
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

func RejectRegistration(ctx context.Context, db *sql.DB, requestID string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE registration_requests SET status='rejected' WHERE id=? AND status='pending'`,
		requestID)
	return err
}

type User struct {
	ID          string
	Username    string
	DisplayName string
	Role        string
	IsBanned    bool
	CreatedAt   time.Time
}

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
		var isBanned int
		rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &isBanned, &createdAtStr)
		u.IsBanned = isBanned != 0
		u.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
		users = append(users, u)
	}
	return users, nil
}

func SetUserBan(ctx context.Context, db *sql.DB, userID string, banned bool) error {
	b := 0
	if banned {
		b = 1
	}
	_, err := db.ExecContext(ctx, `UPDATE users SET is_banned=? WHERE id=?`, b, userID)
	return err
}

func SetUserRole(ctx context.Context, db *sql.DB, userID, role string) error {
	_, err := db.ExecContext(ctx, `UPDATE users SET role=? WHERE id=?`, role, userID)
	return err
}
