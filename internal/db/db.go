// Package db provides the SQLite database connection and migration runner.
package db

import (
	"database/sql"
	"embed"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGO required
)

// migrations embeds every *.sql file from the migrations/ directory into the
// compiled binary so the application can be deployed as a single file.
//
//go:embed migrations/*.sql
var migrations embed.FS

// Connect opens the SQLite database at path, applies all pending migrations,
// and returns a ready-to-use *sql.DB.
//
// The DSN options:
//   - journal_mode=WAL  — Write-Ahead Log mode allows concurrent readers while
//     a writer is active.  Better performance than the default rollback journal.
//   - foreign_keys=ON   — SQLite disables FK enforcement by default; we always
//     want it so ON DELETE CASCADE and REFERENCES constraints work.
//   - busy_timeout=5000 — If the database is locked by another process, retry
//     for up to 5 seconds before returning SQLITE_BUSY.
func Connect(path string) (*sql.DB, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	// SQLite allows only one writer at a time.  Setting MaxOpenConns to 1
	// prevents "database is locked" errors from concurrent write goroutines
	// within this process (the busy_timeout handles contention from external
	// processes).
	db.SetMaxOpenConns(1)

	if err := runMigrations(db); err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}
	return db, nil
}

// runMigrations applies all *.up.sql files in the migrations directory that
// have not yet been applied.  golang-migrate tracks the current version in a
// schema_migrations table it creates automatically.
func runMigrations(db *sql.DB) error {
	src, err := iofs.New(migrations, "migrations")
	if err != nil {
		return err
	}
	driver, err := sqlite.WithInstance(db, &sqlite.Config{})
	if err != nil {
		return err
	}
	m, err := migrate.NewWithInstance("iofs", src, "sqlite", driver)
	if err != nil {
		return err
	}
	// ErrNoChange is not an error — it just means the database is already
	// at the latest migration version.
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return err
	}
	return nil
}
