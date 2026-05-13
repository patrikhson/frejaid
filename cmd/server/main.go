// FrejaID Demo — entry point.
//
// This application demonstrates two modern, password-free authentication methods:
//
//   1. WebAuthn passkeys (FIDO2)
//      The browser's Credential Management API creates a cryptographic key pair
//      on the device.  The private key never leaves the device; we store only
//      the public key.  Login is a challenge-response: we send a random nonce,
//      the device signs it with the private key, and we verify the signature.
//
//   2. Freja eID
//      A Swedish mobile identity app.  Authentication is handled by Apache's
//      mod_auth_openidc module via OpenID Connect.  When the user authenticates,
//      Apache sets HTTP headers (X-Remote-User, X-Freja-Sub, X-Freja-Name) on
//      the forwarded request, and the Go app reads those headers.  The Go app
//      itself never speaks OIDC — Apache is the OIDC client.
//
// Architecture overview:
//   Browser ─── HTTPS ──► Apache (mod_auth_openidc + mod_proxy)
//                                │
//                                │ HTTP (127.0.0.1:8091)
//                                ▼
//                         Go app (this binary)
//                                │
//                                ▼
//                         SQLite database
//
// For paths under /auth/freja/* Apache requires Freja authentication before
// proxying.  All other paths are proxied unconditionally.
package main

import (
	"context"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/joho/godotenv"
	frejaid "github.com/paftech/frejaid"
	"github.com/paftech/frejaid/internal/admin"
	"github.com/paftech/frejaid/internal/auth"
	"github.com/paftech/frejaid/internal/config"
	"github.com/paftech/frejaid/internal/db"
	"github.com/paftech/frejaid/internal/home"
	"github.com/paftech/frejaid/internal/hooks"
	"github.com/paftech/frejaid/internal/mail"
	"github.com/paftech/frejaid/internal/middleware"
	"github.com/paftech/frejaid/internal/user"
)

func main() {
	// Ensure browsers receive correct Content-Type headers for static assets.
	// Some systems have incomplete or outdated MIME type databases.
	mime.AddExtensionType(".css", "text/css; charset=utf-8")
	mime.AddExtensionType(".js", "application/javascript; charset=utf-8")
	mime.AddExtensionType(".svg", "image/svg+xml")
	mime.AddExtensionType(".ico", "image/x-icon")

	// Load .env if present.  Silently ignored if the file does not exist
	// (environment variables are already set in production via systemd).
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Open the SQLite database and run any pending migrations automatically.
	database, err := db.Connect(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer database.Close()
	log.Println("database connected and migrations applied")

	// Initialise the WebAuthn relying party.
	// RPID    — must match the domain the browser is visiting (no port).
	// RPOrigins — the full origin(s) allowed to create/use credentials.
	//             Must match window.location.origin in the browser.
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.WebAuthnRPDisplayName,
		RPID:          cfg.WebAuthnRPID,
		RPOrigins:     []string{cfg.WebAuthnRPOrigin},
	})
	if err != nil {
		log.Fatalf("webauthn: %v", err)
	}

	mailer := mail.New(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPFrom)

	// ── Integration hooks ─────────────────────────────────────────────────────
	// Populate these to connect FrejaID events to your application logic.
	// Any field left nil is silently skipped.  See internal/hooks/hooks.go for
	// the full list and documentation of each hook.
	appHooks := &hooks.Hooks{
		// OnUserCreated: func(ctx context.Context, u hooks.User) {
		//     // Create the user's record in your own database.
		//     mydb.CreateUser(ctx, u.ID, u.Email, u.DisplayName)
		// },
		// OnLogin: func(ctx context.Context, userID string, method hooks.LoginMethod) {
		//     // Write an audit log entry.
		//     audit.Log(ctx, userID, "login", string(method))
		// },
		// OnEmailChanged: func(ctx context.Context, userID, oldEmail, newEmail string) {
		//     // Update the email reference in your own database.
		//     mydb.UpdateEmail(ctx, userID, newEmail)
		// },
	}

	// auth.Handler owns the core authentication flows: registration, login,
	// passkey management, Freja linking, and credential reset.
	authHandler := auth.NewHandler(database, wa, mailer, appHooks, cfg.AppBaseURL, cfg.SessionSecret, cfg.IsProd, cfg.AdminEmails)

	// Periodically delete expired sessions so the sessions table stays small.
	go func() {
		t := time.NewTicker(1 * time.Hour)
		defer t.Stop()
		for range t.C {
			auth.CleanupSessions(context.Background(), database)
		}
	}()

	mux := http.NewServeMux()

	// Health check endpoint for load balancers / uptime monitors.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Register route groups.
	// requireAuth and requireAdmin are middleware functions that redirect or
	// reject unauthenticated / unauthorised requests respectively.
	requireAuth := auth.RequireAuth(database, cfg.SessionSecret)
	requireAdmin := auth.RequireRole(database, cfg.SessionSecret, "admin")
	// rateLimiter caps unauthenticated POST requests per client IP per hour.
	// This throttles registration spam, login probing, and credential-reset floods.
	rateLimiter := middleware.NewIPRateLimiter(cfg.RateLimitPerHour)

	authHandler.RegisterRoutes(mux, requireAuth, rateLimiter)
	user.NewHandler(database, mailer, appHooks, cfg.AppBaseURL, cfg.IsProd).RegisterRoutes(mux, requireAuth)
	admin.NewHandler(database, mailer, appHooks, cfg.AppBaseURL).RegisterRoutes(mux, requireAdmin)
	home.NewHandler(database).RegisterRoutes(mux, requireAuth)

	// Serve static assets (CSS, JS, images) from the embedded filesystem.
	// The embed.FS is defined in assets.go at the repository root.
	staticSub, err := fs.Sub(frejaid.StaticFiles, "static")
	if err != nil {
		log.Fatalf("static embed: %v", err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Wrap with middleware applied to every request:
	//   SecurityHeaders — sets X-Frame-Options, X-Content-Type-Options, etc.
	//   Logging         — logs method, path, and duration.
	handler := middleware.Logging(middleware.SecurityHeaders(mux))

	srv := &http.Server{
		Addr:              cfg.BindAddr + ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("listening on %s:%s (env=%s)", cfg.BindAddr, cfg.Port, cfg.AppEnv)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	// Wait for SIGINT (Ctrl-C) or SIGTERM (systemd stop) then shut down cleanly.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("shutdown: %v", err)
	}
	log.Println("stopped")
}
