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
	"github.com/paftech/frejaid/internal/mail"
	"github.com/paftech/frejaid/internal/middleware"
	"github.com/paftech/frejaid/internal/user"
)

func main() {
	mime.AddExtensionType(".css", "text/css; charset=utf-8")
	mime.AddExtensionType(".js", "application/javascript; charset=utf-8")
	mime.AddExtensionType(".svg", "image/svg+xml")
	mime.AddExtensionType(".ico", "image/x-icon")

	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	database, err := db.Connect(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer database.Close()
	log.Println("database connected and migrations applied")

	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.WebAuthnRPDisplayName,
		RPID:          cfg.WebAuthnRPID,
		RPOrigins:     []string{cfg.WebAuthnRPOrigin},
	})
	if err != nil {
		log.Fatalf("webauthn: %v", err)
	}

	mailer := mail.New(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPFrom)

	authHandler := auth.NewHandler(database, wa, mailer, cfg.AppBaseURL, cfg.SessionSecret, cfg.IsProd)

	go func() {
		t := time.NewTicker(1 * time.Hour)
		defer t.Stop()
		for range t.C {
			auth.CleanupSessions(context.Background(), database)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	authHandler.RegisterRoutes(mux, auth.RequireAuth(database))
	user.NewHandler(database, mailer, cfg.AppBaseURL, cfg.IsProd).RegisterRoutes(mux, auth.RequireAuth(database))
	admin.NewHandler(database, mailer, cfg.AppBaseURL).RegisterRoutes(mux, auth.RequireRole(database, "admin"))
	home.NewHandler(database).RegisterRoutes(mux, auth.RequireAuth(database))

	staticSub, err := fs.Sub(frejaid.StaticFiles, "static")
	if err != nil {
		log.Fatalf("static embed: %v", err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	handler := middleware.Logging(middleware.SecurityHeaders(mux))

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("listening on :%s (env=%s)", cfg.Port, cfg.AppEnv)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

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
