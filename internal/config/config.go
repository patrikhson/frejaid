// Package config loads application configuration from environment variables.
// Copy .env.example to .env, fill in the values, and the app will load it
// automatically via godotenv at startup.
package config

import (
	"fmt"
	"os"
	"strings"
)

// Config holds all runtime configuration for the application.
type Config struct {
	// AppEnv distinguishes environments: "development" or "production".
	// In production, SESSION_SECRET is required and cookies are Secure.
	AppEnv string

	// Port is the TCP port the HTTP server listens on (default: 8091).
	// In production the app sits behind Apache which handles TLS termination.
	Port string

	// IsProd is true when AppEnv == "production".
	IsProd bool

	// DatabasePath is the filesystem path to the SQLite database file.
	DatabasePath string

	// SessionSecret is used as the session cookie value domain — it must be
	// a long random string in production (generate with: openssl rand -hex 32).
	// In development a placeholder is used automatically.
	SessionSecret string

	// WebAuthn settings — these must match what the browser sees.
	//
	// RPID (Relying Party ID): the domain name only, no scheme, no port.
	//   e.g. "example.com" for https://example.com
	//   e.g. "localhost" for local development
	//   The browser enforces that RPID is a registrable-domain suffix of the
	//   page's origin, so "example.com" covers "app.example.com" too.
	//
	// RPOrigin: the full origin the users' browser sees, including scheme and
	//   port if non-standard.  Must match window.location.origin exactly.
	//   e.g. "https://example.com" or "http://localhost:8091"
	//
	// RPDisplayName: human-readable name shown in the browser's passkey prompt.
	WebAuthnRPID          string
	WebAuthnRPOrigin      string
	WebAuthnRPDisplayName string

	// AppBaseURL is the full base URL used when constructing links in emails.
	// Must not end with a slash.  e.g. "https://example.com"
	AppBaseURL string

	// SMTP settings for outbound email.
	// STARTTLS is attempted automatically when the server advertises it.
	// Leave SMTP_USER/PASS empty to send without authentication (e.g. local relay).
	SMTPHost string
	SMTPPort string
	SMTPUser string
	SMTPPass string
	SMTPFrom string

	// AdminEmails is a comma-separated list of email addresses that are
	// automatically approved and granted the "admin" role on their first
	// registration.  Use this to bootstrap the first admin without a
	// chicken-and-egg approval problem.
	AdminEmails []string
}

// Load reads environment variables and returns a validated Config.
func Load() (*Config, error) {
	c := &Config{
		AppEnv:                getEnv("APP_ENV", "development"),
		Port:                  getEnv("PORT", "8091"),
		DatabasePath:          getEnv("DATABASE_PATH", "./frejaid.db"),
		SessionSecret:         getEnv("SESSION_SECRET", ""),
		WebAuthnRPID:          getEnv("WEBAUTHN_RPID", "localhost"),
		WebAuthnRPOrigin:      getEnv("WEBAUTHN_RPORIGIN", "http://localhost:8091"),
		WebAuthnRPDisplayName: getEnv("WEBAUTHN_RPDISPLAYNAME", "FrejaID Demo"),
		AppBaseURL:            getEnv("APP_BASE_URL", "http://localhost:8091"),
		SMTPHost:              getEnv("SMTP_HOST", ""),
		SMTPPort:              getEnv("SMTP_PORT", "25"),
		SMTPUser:              getEnv("SMTP_USER", ""),
		SMTPPass:              getEnv("SMTP_PASS", ""),
		SMTPFrom:              getEnv("SMTP_FROM", ""),
		AdminEmails:           splitEmails(getEnv("ADMIN_EMAIL", "")),
	}

	c.IsProd = c.AppEnv == "production"

	// Require a real secret in production to prevent accidental deployment
	// with the placeholder value.
	if c.SessionSecret == "" || c.SessionSecret == "changeme" {
		if c.IsProd {
			return nil, fmt.Errorf("SESSION_SECRET must be set in production (generate with: openssl rand -hex 32)")
		}
		c.SessionSecret = "dev-session-secret-not-for-production"
	}

	return c, nil
}

// getEnv returns the value of the environment variable key, or fallback if
// the variable is unset or empty.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// splitEmails splits a comma-separated list of email addresses, trimming
// whitespace and dropping empty entries.
func splitEmails(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			result = append(result, t)
		}
	}
	return result
}
