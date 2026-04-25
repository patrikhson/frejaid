# FrejaID Demo

A reference implementation of password-free authentication for Swedish web services, demonstrating two complementary methods:

- **WebAuthn passkeys** — FIDO2 / W3C Web Authentication. The browser creates a cryptographic key pair on the device; the private key never leaves it. Login is a signed challenge, not a password.
- **Freja eID** — A Swedish mobile identity app, authenticated via OpenID Connect. The user approves a request in the app; no credential is stored on the web server.

This repository exists as a working, deployable demo and as a reference for integrating these authentication methods into your own service. Both methods can coexist on the same account.

---

## Table of contents

1. [How the two auth methods work](#how-the-two-auth-methods-work)
2. [System architecture](#system-architecture)
3. [User flows](#user-flows)
4. [Integration — Scenario 1A: wrapping an existing app](#scenario-1a-wrapping-an-existing-app)
5. [Integration — Scenario 1B: building a new Go app](#scenario-1b-building-a-new-go-app)
6. [Setup and deployment](#setup-and-deployment)
7. [Configuration reference](#configuration-reference)
8. [Database schema](#database-schema)
9. [Project layout](#project-layout)

---

## How the two auth methods work

### WebAuthn passkeys

Passkeys use public-key cryptography. At registration the authenticator (Face ID, Touch ID, a YubiKey…) generates a key pair and keeps the **private key locked to the device** — it cannot be exported or phished. The server stores only the public key.

At login:

```
Server                          Browser / Authenticator
  │                                      │
  │── random challenge ─────────────────►│
  │                                      │ user verifies (biometric / PIN)
  │◄── signature over challenge ─────────│ (private key never leaves device)
  │                                      │
  │  verify signature with stored        │
  │  public key → authenticated          │
```

The protocol is defined by the [W3C Web Authentication spec](https://www.w3.org/TR/webauthn/). This demo uses the [go-webauthn](https://github.com/go-webauthn/webauthn) library.

**Binary encoding:** the WebAuthn browser API uses `ArrayBuffer` for all binary values (challenges, credential IDs, keys). JSON cannot carry raw binary, so values are encoded as **base64url** (URL-safe base64 without padding) for transport. The JavaScript helpers `base64ToBuffer` and `bufferToBase64` in the login/registration pages handle this conversion.

**Sign count:** the authenticator increments a counter on every use. If the server sees a counter that is lower than the stored value, the credential may have been cloned. This demo stores and checks the sign count on every login.

**Backup flags:** modern passkeys can be synced across devices (iCloud Keychain, Google Password Manager). The `backup_eligible` and `backup_state` flags record whether a given credential is cloud-synced. This demo stores them but does not enforce policy on them.

---

### Freja eID

[Freja eID](https://frejaeid.com) is a Swedish electronic identity service. Authentication uses OpenID Connect (OIDC), but the Go application never speaks OIDC directly. Instead, **Apache's mod_auth_openidc module** handles the full OIDC flow and passes the authenticated identity to Go as HTTP request headers:

```
Browser                    Apache                     Freja
  │                           │                          │
  │── GET /auth/freja/login──►│                          │
  │                           │── OIDC redirect ────────►│
  │◄── redirect to Freja ─────│                          │
  │                                                      │
  │  user approves in Freja app                          │
  │                                                      │
  │◄── OIDC callback ─────────│◄─ authorization code ────│
  │                           │   (Apache validates)     │
  │                           │                          │
  │                           │── proxies to Go with:    │
  │                           │   X-Remote-User: alice@example.com
  │                           │   X-Freja-Sub:   <opaque stable ID>
  │                           │   X-Freja-Name:  Alice Svensson
  │◄── response ──────────────│◄─ Go reads headers ───   │
```

The Go app trusts these headers because it only listens on `127.0.0.1` — Apache is the only process that can reach it.

**Subject vs email:** Freja provides a stable opaque `sub` claim (the subject identifier) that does not change even if the user updates their email address. This demo stores both and uses the subject as the primary lookup key, with email as a fallback.

---

## System architecture

```
                        ┌─────────────────────────────────────┐
                        │              Apache                 │
                        │                                     │
  Browser ──── HTTPS ──►│  mod_ssl          (TLS termination) │
                        │  mod_auth_openidc (Freja OIDC)      │
                        │  mod_proxy        (reverse proxy)   │
                        │  mod_auth_request (session check)   │
                        └──────────────┬──────────────────────┘
                                       │ HTTP  127.0.0.1:8091
                                       ▼
                        ┌─────────────────────────────────────┐
                        │           Go application            │
                        │                                     │
                        │  /auth/*   — auth flows             │
                        │  /admin/*  — admin panel            │
                        │  /settings/* — user settings        │
                        │  /auth/check — session check API    │
                        └──────────────┬──────────────────────┘
                                       │
                                       ▼
                        ┌─────────────────────────────────────┐
                        │         SQLite database             │
                        │  (WAL mode, single writer)          │
                        └─────────────────────────────────────┘
```

Apache routes:

| Path pattern | Apache behaviour |
|---|---|
| `/auth/freja/*` | Requires Freja OIDC authentication; sets X-Remote-User etc. |
| `/auth/check` | Proxied to Go as-is; Go returns 200 or 401 |
| Everything else | Proxied to Go as-is |

---

## User flows

### Registration

```
1. User fills in name + email at /auth/request
2. Verification email sent with a one-time link
3. User clicks link → email confirmed → chooses auth method:

   ┌─ Passkey path ───────────────────────────────────────────┐
   │ 4a. Browser calls navigator.credentials.create()         │
   │     Authenticator generates key pair on device           │
   │     Public key sent to server and stored                 │
   │ 5a. User waits for admin approval                        │
   │ 6a. Admin approves → account created → approval email    │
   │ 7a. User logs in with passkey                            │
   └──────────────────────────────────────────────────────────┘

   ┌─ Freja eID path ─────────────────────────────────────────┐
   │ 4b. Apache redirects to Freja OIDC                       │
   │     User approves in Freja app                           │
   │     Apache sets X-Remote-User, X-Freja-Sub headers       │
   │ 5b. User waits for admin approval                        │
   │ 6b. Admin approves → account created → approval email    │
   │ 7b. User logs in via Freja eID                           │
   └──────────────────────────────────────────────────────────┘
```

**Admin bootstrap:** set `ADMIN_EMAIL` in `.env` to auto-approve the first admin without needing an existing admin to do it.

### Login

**Passkey:**
```
1. User enters email → POST /auth/login/begin
2. Server returns challenge + list of credential IDs for this user
3. Browser calls navigator.credentials.get() — user verifies (Face ID etc.)
4. Authenticator signs challenge with private key
5. POST /auth/login/finish — server verifies signature → session created
```

**Freja eID:**
```
1. User clicks "Log in with Freja eID" → Apache does OIDC
2. User approves in Freja app
3. Apache sets headers → Go looks up user by subject/email → session created
```

### Credential reset

When a user loses access to their passkey (broken device) or Freja account:

```
1. User tries to register with existing email → "Account exists" page
2. User submits a credential reset request (passkey or Freja)
3. All admins notified by email
4. Admin reviews request in /admin/credential-resets, clicks Approve
5. User receives a 48-hour setup link by email

   Passkey reset: user registers new passkey via the link
   Freja reset:   user visits link → Apache does Freja OIDC
                  → Freja email verified against account → identity linked
```

### Linking / unlinking Freja eID (for existing accounts)

A user with a passkey account can add Freja eID from Account Settings:

```
1. User clicks "Link Freja eID" → Apache does OIDC
2. Go reads Freja identity from headers
3. Confirmation page shown (with a short-lived token)
4. User confirms → identity stored in user_identities
```

Unlinking is only permitted if the user has at least one passkey as a fallback.

---

## Scenario 1A: wrapping an existing app

Use this when you have an existing web application (in any language) and want to add passkey + Freja eID authentication in front of it without modifying the app.

FrejaID runs as a standalone service. Apache uses `mod_auth_request` to call FrejaID's `/auth/check` endpoint before every request. If the check returns 200, Apache injects the user's identity as request headers and proxies the request to your app. If it returns 401, Apache redirects to the FrejaID login page.

### What your existing app receives

On every authenticated request Apache adds four headers:

| Header | Value | Notes |
|---|---|---|
| `X-FrejaID-User-ID` | `3f2a1b4c-…` | Stable UUID; use as the foreign key in your database |
| `X-FrejaID-User-Email` | `alice@example.com` | The user's email / login name |
| `X-FrejaID-User-Role` | `admin` | `passive`, `active`, or `admin` |
| `X-FrejaID-User-Name` | `Alice Svensson` | Display name; falls back to email if unset |

Your app reads these headers and treats the request as authenticated. It does not need to understand cookies, sessions, WebAuthn, or OIDC.

The auth method (passkey vs Freja eID) is intentionally not exposed — your app should treat both identically.

### Security

Apache **must** strip any client-supplied `X-FrejaID-*` headers before adding its own, otherwise a malicious client could forge an identity. The example config below does this.

Your Go app **must** listen on `127.0.0.1` only (not `0.0.0.0`) so it is unreachable without going through Apache.

### Apache configuration

See [`config/apache-existing-app.conf`](config/apache-existing-app.conf) for a complete, annotated example. Key sections:

```apache
# Gate every request through FrejaID's session check
auth_request /auth/check

# Strip any client-supplied identity headers (security)
RequestHeader unset X-FrejaID-User-ID
RequestHeader unset X-FrejaID-User-Email
RequestHeader unset X-FrejaID-User-Role
RequestHeader unset X-FrejaID-User-Name

# Copy identity from /auth/check response onto the forwarded request
auth_request_set %{ENV:FREJAID_USER_ID}    %{resp_header:X-FrejaID-User-ID}
RequestHeader    set X-FrejaID-User-ID     %{FREJAID_USER_ID}e

# ... (repeat for Email, Role, Name)

# Proxy to your existing app
ProxyPass / http://127.0.0.1:YOUR_PORT/
```

### Reading the headers in your app

**PHP:**
```php
$userID = $_SERVER['HTTP_X_FREJAID_USER_ID'] ?? null;
if (!$userID) { /* should not happen — Apache already checked */ }
```

**Python (Flask):**
```python
user_id = request.headers.get('X-FrejaID-User-ID')
```

**Node.js (Express):**
```js
const userID = req.headers['x-frejaid-user-id'];
```

**Go:**
```go
userID := r.Header.Get("X-FrejaID-User-ID")
```

### OnUserCreated hook for 1A

Your existing app may need to create its own user record the first time it sees a new `X-FrejaID-User-ID`. You can do this **lazily** (create the record on first request if it does not exist) without any hook at all.

If you prefer to be notified eagerly, FrejaID provides `OnUserCreated` in `cmd/server/main.go`:

```go
appHooks := &hooks.Hooks{
    OnUserCreated: func(ctx context.Context, u hooks.User) {
        // Called once when the admin approves a registration.
        // Make an HTTP call to your app, write to a shared database, etc.
        myapp.ProvisionUser(u.ID, u.Email)
    },
}
```

---

## Scenario 1B: building a new Go app

Use this when you are building a new application from scratch and Go is your language of choice.

Fork or embed this repository. FrejaID provides a `hooks.Hooks` struct with callbacks for every meaningful authentication event. Populate the ones your application needs in `cmd/server/main.go` and add your application's own routes to the same HTTP mux.

### The hooks system

All hooks are optional function fields. Nil fields are silently skipped.

```go
// cmd/server/main.go
appHooks := &hooks.Hooks{

    // Called once when a new user account is created after admin approval.
    // This is where you bootstrap the user in your own database.
    OnUserCreated: func(ctx context.Context, u hooks.User) {
        mydb.CreateProfile(ctx, mydb.Profile{
            ID:    u.ID,    // use FrejaID's UUID as your own user key
            Email: u.Email,
            Name:  u.DisplayName,
            Role:  u.Role,
        })
    },

    // Called after every successful login.
    OnLogin: func(ctx context.Context, userID string, method hooks.LoginMethod) {
        audit.Log(ctx, userID, "login", string(method))
        mydb.UpdateLastSeen(ctx, userID)
    },

    // Called after a confirmed email address change.
    OnEmailChanged: func(ctx context.Context, userID, _, newEmail string) {
        mydb.UpdateEmail(ctx, userID, newEmail)
    },

    // Called when an admin changes a user's role.
    OnRoleChanged: func(ctx context.Context, userID, newRole string) {
        mydb.UpdateRole(ctx, userID, newRole)
    },
}
```

### Available hooks

| Hook | When it fires | 1A useful? | 1B useful? |
|---|---|---|---|
| `OnUserCreated` | Admin approves a registration | Yes | Yes |
| `OnLogin` | Successful login | No | Yes |
| `OnLogout` | Explicit logout | No | Yes |
| `OnEmailChanged` | User confirms email change | Yes | Yes |
| `OnFrejaLinked` | User links Freja eID | No | Yes |
| `OnFrejaUnlinked` | User removes Freja eID | No | Yes |
| `OnUserBanned` | Admin bans a user | No | Yes |
| `OnUserUnbanned` | Admin unbans a user | No | Yes |
| `OnRoleChanged` | Admin changes a user's role | No | Yes |

### Adding your own routes

The HTTP mux is created in `main.go` before FrejaID registers its routes. Add your own handlers after:

```go
// FrejaID routes
authHandler.RegisterRoutes(mux, requireAuth)

// Your application routes (all protected by requireAuth)
mux.Handle("GET /dashboard", requireAuth(http.HandlerFunc(myapp.Dashboard)))
mux.Handle("GET /api/data",  requireAuth(http.HandlerFunc(myapp.Data)))
```

The authenticated user's ID and role are available from the request context in any handler behind `requireAuth`:

```go
func (h *MyHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
    userID := middleware.GetUserID(r)
    role   := middleware.GetUserRole(r)
    // ... your logic
}
```

---

## Setup and deployment

### Prerequisites

- Go 1.21+
- SQLite (bundled — no system SQLite required; the driver is pure Go)
- Apache 2.4 with: `mod_ssl`, `mod_proxy`, `mod_proxy_http`, `mod_headers`, `mod_auth_openidc` (for Freja eID), `mod_auth_request` (for Scenario 1A)
- A Freja eID OIDC client registration (contact Freja / Verisec)
- An SMTP relay for outbound email

### Local development

```bash
git clone https://github.com/patrikhson/frejaid
cd frejaid
cp .env.example .env
# Edit .env — at minimum set WEBAUTHN_RPID=localhost and APP_BASE_URL
go run ./cmd/server
```

The server starts on port 8091. Open http://localhost:8091/auth/request to register.

For local development, Freja eID is not available (it requires HTTPS and a registered OIDC client). All passkey flows work normally.

### Production deployment

**1. Build the binary:**
```bash
go build -ldflags="-s -w" -o frejaid ./cmd/server
```

**2. Install:**
```bash
sudo mkdir -p /opt/frejaid
sudo cp frejaid /opt/frejaid/frejaid
sudo cp .env.example /opt/frejaid/.env
# Edit /opt/frejaid/.env with production values
```

**3. systemd service:**

Use the template in [`config/frejaid.service`](config/frejaid.service):
```bash
sudo cp config/frejaid.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now frejaid
```

**4. Apache:**

For FrejaID itself: [`config/apache-frejaid-le-ssl.conf`](config/apache-frejaid-le-ssl.conf)

For wrapping an existing app (Scenario 1A): [`config/apache-existing-app.conf`](config/apache-existing-app.conf)

---

## Configuration reference

All configuration is via environment variables.  Copy `.env.example` to `.env`:

| Variable | Default | Description |
|---|---|---|
| `APP_ENV` | `development` | Set to `production` to enforce SESSION_SECRET and enable Secure cookies |
| `PORT` | `8091` | TCP port the Go server listens on |
| `DATABASE_PATH` | `./frejaid.db` | Path to the SQLite database file |
| `SESSION_SECRET` | *(required in prod)* | Random secret for session integrity. Generate: `openssl rand -hex 32` |
| `WEBAUTHN_RPID` | `localhost` | Domain name only (no scheme, no port). Must match the domain users visit. e.g. `example.com` |
| `WEBAUTHN_RPORIGIN` | `http://localhost:8091` | Full origin the browser sees. Must match `window.location.origin`. e.g. `https://example.com` |
| `WEBAUTHN_RPDISPLAYNAME` | `FrejaID Demo` | Name shown in the browser's passkey prompt |
| `APP_BASE_URL` | `http://localhost:8091` | Base URL for links in emails. No trailing slash. |
| `ADMIN_EMAIL` | *(empty)* | Comma-separated email(s) auto-approved as admin on first registration |
| `SMTP_HOST` | *(empty)* | SMTP relay hostname |
| `SMTP_PORT` | `25` | SMTP port |
| `SMTP_USER` | *(empty)* | SMTP username (leave empty for unauthenticated relay) |
| `SMTP_PASS` | *(empty)* | SMTP password |
| `SMTP_FROM` | *(empty)* | Envelope From address for outbound email |

---

## Database schema

FrejaID uses SQLite with [golang-migrate](https://github.com/golang-migrate/migrate) for schema management. Migrations run automatically on startup.

| Table | Purpose |
|---|---|
| `users` | Approved user accounts |
| `sessions` | Server-side session store (30-day rolling sessions) |
| `webauthn_credentials` | Registered passkeys (one user can have many) |
| `user_identities` | Linked external identities (Freja eID) |
| `registration_requests` | Multi-step new-user registrations awaiting admin approval |
| `credential_reset_requests` | Requests to replace a lost passkey or Freja identity |
| `webauthn_login_sessions` | Short-lived challenge state for passkey login (5 min) |
| `webauthn_add_sessions` | Short-lived challenge state for adding a second passkey |
| `freja_link_confirmations` | Short-lived tokens for Freja eID linking |
| `email_change_tokens` | Short-lived tokens for email address changes |

See [`internal/db/migrations/`](internal/db/migrations/) for the full annotated schema.

---

## Project layout

```
cmd/server/
  main.go                   Entry point; wires everything together;
                            THIS is where you populate appHooks for 1B

config/
  apache-frejaid-le-ssl.conf  Apache config for FrejaID itself (HTTPS + Freja OIDC)
  apache-frejaid.conf         HTTP → HTTPS redirect for FrejaID
  apache-existing-app.conf    Apache config for Scenario 1A (wrapping your app)
  frejaid.service             systemd service unit

internal/
  auth/
    check.go      GET /auth/check — session check for Apache mod_auth_request (1A)
    freja.go      Freja eID flows (register, login, link, unlink, reset)
    handler.go    Registration and passkey login flows
    passkeys.go   Passkey management (add, rename, delete)
    reset.go      Credential reset flow
    session.go    Session create / validate / delete; RequireAuth middleware
  admin/
    handler.go    Admin panel HTTP handlers
    repository.go Admin database queries
  config/
    config.go     Loads and validates environment variables
  db/
    db.go         SQLite connection and migration runner
    migrations/   SQL migration files (annotated schema)
  home/
    handler.go    Authenticated home page / dashboard
  hooks/
    hooks.go      Integration callbacks for the host application (1B)
  layout/
    layout.go     Shared HTML page wrappers
  mail/
    mail.go       SMTP email sender
  middleware/
    middleware.go Logging, security headers, context helpers
  user/
    handler.go    User self-service (profile, email change)

static/
  css/            Compiled Tailwind CSS
assets.go         Embeds static files into the binary
```
