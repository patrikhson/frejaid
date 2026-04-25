// Package hooks defines the integration points between FrejaID and the host
// application.  There are two integration scenarios:
//
// Scenario 1A — wrapping an existing app (language-agnostic)
//
//	FrejaID runs as a standalone service.  Apache uses mod_auth_request to call
//	GET /auth/check before every request.  The existing app receives the
//	authenticated user's identity as request headers set by Apache:
//
//	    X-FrejaID-User-ID    — stable UUID; use as the foreign key in your DB
//	    X-FrejaID-User-Email — email address / login name
//	    X-FrejaID-User-Role  — "passive", "active", or "admin"
//	    X-FrejaID-User-Name  — display name (falls back to email if unset)
//
//	For 1A, only OnUserCreated and OnEmailChanged are typically useful.
//	Everything else (bans, role changes, logouts) is handled automatically:
//	the next request gets a 401 or an updated header.
//
// Scenario 1B — new Go app built on top of FrejaID
//
//	The host app embeds FrejaID and populates the Hooks struct in main.go.
//	All hooks are available.  See the commented examples in cmd/server/main.go.
//
// Usage
//
//	Populate the fields you need; leave the rest nil — nil hooks are skipped.
//
//	    appHooks := &hooks.Hooks{
//	        OnUserCreated: func(ctx context.Context, u hooks.User) {
//	            mydb.CreateProfile(ctx, u.ID, u.Email)
//	        },
//	    }
//
// Guarantees
//
//	Hooks are called synchronously inside the HTTP handler after the database
//	write succeeds.  They have no return value; handle errors inside the hook.
//	Hooks do not run inside a FrejaID database transaction.
package hooks

import "context"

// LoginMethod identifies the credential used to authenticate.
type LoginMethod string

const (
	LoginPasskey LoginMethod = "passkey" // WebAuthn / FIDO2
	LoginFreja   LoginMethod = "freja"   // Freja eID via Apache OIDC
)

// User carries data about a newly approved user, passed to OnUserCreated.
type User struct {
	ID          string      // stable UUID — same as users.id in FrejaID's database
	Email       string      // email address (also the login username)
	DisplayName string      // may be empty if the user has not set one
	Role        string      // "passive", "active", or "admin"
	Provider    LoginMethod // which credential was registered at sign-up
}

// Hooks holds all integration callbacks as optional function fields.
// Nil fields are silently skipped.
type Hooks struct {
	// OnUserCreated is called once when an admin approves a registration and
	// the user account is created.  This is the primary integration point:
	// create the user's record in your own database, grant default permissions,
	// send a custom welcome email, etc.
	//
	// Relevant for: 1A and 1B.
	OnUserCreated func(ctx context.Context, user User)

	// OnLogin is called after every successful login (passkey or Freja eID).
	// Use it for audit logs, "last seen" tracking, or concurrent-session limits.
	// The method argument tells you which credential was used, but most
	// applications should treat both identically.
	//
	// Relevant for: 1B.  In 1A the existing app sees every authenticated
	// request and can track activity itself.
	OnLogin func(ctx context.Context, userID string, method LoginMethod)

	// OnLogout is called when a user explicitly logs out.
	// Note: sessions can also expire passively without triggering this hook.
	//
	// Relevant for: 1B.
	OnLogout func(ctx context.Context, userID string)

	// OnEmailChanged is called after the user confirms an email address change.
	// Update any email references in your own database.
	// oldEmail is empty in the current implementation (not stored at change
	// time); query your own database if you need it.
	//
	// Relevant for: 1A and 1B.
	OnEmailChanged func(ctx context.Context, userID, oldEmail, newEmail string)

	// OnFrejaLinked is called when a user adds Freja eID as a login method.
	//
	// Relevant for: 1B.
	OnFrejaLinked func(ctx context.Context, userID, frejaEmail, frejaSub string)

	// OnFrejaUnlinked is called when a user removes their Freja eID.
	//
	// Relevant for: 1B.
	OnFrejaUnlinked func(ctx context.Context, userID string)

	// OnUserBanned is called when an admin bans a user.
	// In 1A, the next request from a banned user receives a 401 automatically.
	// In 1B, use this to revoke tokens in other systems.
	//
	// Relevant for: 1B.
	OnUserBanned func(ctx context.Context, userID string)

	// OnUserUnbanned is called when an admin reinstates a banned user.
	//
	// Relevant for: 1B.
	OnUserUnbanned func(ctx context.Context, userID string)

	// OnRoleChanged is called when an admin changes a user's role.
	// In 1A, the new role appears in X-FrejaID-User-Role on the next request.
	// In 1B, use this to sync permissions in your own system.
	//
	// Relevant for: 1B.
	OnRoleChanged func(ctx context.Context, userID, newRole string)
}

// ─── Safe callers ─────────────────────────────────────────────────────────────
// Called from handler code.  Each checks for nil before invoking.

func (h *Hooks) CallOnUserCreated(ctx context.Context, user User) {
	if h != nil && h.OnUserCreated != nil {
		h.OnUserCreated(ctx, user)
	}
}

func (h *Hooks) CallOnLogin(ctx context.Context, userID string, method LoginMethod) {
	if h != nil && h.OnLogin != nil {
		h.OnLogin(ctx, userID, method)
	}
}

func (h *Hooks) CallOnLogout(ctx context.Context, userID string) {
	if h != nil && h.OnLogout != nil {
		h.OnLogout(ctx, userID)
	}
}

func (h *Hooks) CallOnEmailChanged(ctx context.Context, userID, oldEmail, newEmail string) {
	if h != nil && h.OnEmailChanged != nil {
		h.OnEmailChanged(ctx, userID, oldEmail, newEmail)
	}
}

func (h *Hooks) CallOnFrejaLinked(ctx context.Context, userID, frejaEmail, frejaSub string) {
	if h != nil && h.OnFrejaLinked != nil {
		h.OnFrejaLinked(ctx, userID, frejaEmail, frejaSub)
	}
}

func (h *Hooks) CallOnFrejaUnlinked(ctx context.Context, userID string) {
	if h != nil && h.OnFrejaUnlinked != nil {
		h.OnFrejaUnlinked(ctx, userID)
	}
}

func (h *Hooks) CallOnUserBanned(ctx context.Context, userID string) {
	if h != nil && h.OnUserBanned != nil {
		h.OnUserBanned(ctx, userID)
	}
}

func (h *Hooks) CallOnUserUnbanned(ctx context.Context, userID string) {
	if h != nil && h.OnUserUnbanned != nil {
		h.OnUserUnbanned(ctx, userID)
	}
}

func (h *Hooks) CallOnRoleChanged(ctx context.Context, userID, newRole string) {
	if h != nil && h.OnRoleChanged != nil {
		h.OnRoleChanged(ctx, userID, newRole)
	}
}
