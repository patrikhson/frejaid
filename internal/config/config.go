package config

import (
	"fmt"
	"os"
)

type Config struct {
	AppEnv string
	Port   string
	IsProd bool

	DatabasePath string

	SessionSecret string

	WebAuthnRPID          string
	WebAuthnRPOrigin      string
	WebAuthnRPDisplayName string

	AppBaseURL string

	SMTPHost string
	SMTPPort string
	SMTPUser string
	SMTPPass string
	SMTPFrom string
}

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
	}

	c.IsProd = c.AppEnv == "production"

	if c.SessionSecret == "" || c.SessionSecret == "changeme" {
		if c.IsProd {
			return nil, fmt.Errorf("SESSION_SECRET must be set in production")
		}
		c.SessionSecret = "dev-session-secret-not-for-production"
	}

	return c, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
