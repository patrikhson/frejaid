// Package mail provides a minimal SMTP email sender.
//
// All outbound email uses plain text bodies with quoted-printable encoding so
// that non-ASCII characters (names, accented letters) are transmitted safely
// regardless of whether the relay supports 8BITMIME or SMTPUTF8.
//
// STARTTLS is attempted automatically when the server offers it.  TLS
// certificate verification is skipped for localhost connections (dev setups
// often use self-signed certs); it is enforced for all other hosts.
package mail

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"strings"
)

// Mailer holds SMTP connection parameters.
type Mailer struct {
	host string
	port string
	from string // envelope From address
	user string // SMTP AUTH username (empty = no auth)
	pass string // SMTP AUTH password
}

// New creates a Mailer.  Pass empty user/pass to skip SMTP AUTH (e.g. local relay).
func New(host, port, user, pass, from string) *Mailer {
	return &Mailer{host: host, port: port, from: from, user: user, pass: pass}
}

// encodeHeader encodes a header value with RFC 2047 base64 ("B encoding")
// if the value contains any non-ASCII character, so that names like "Åsa"
// arrive intact regardless of the relay chain.
func encodeHeader(s string) string {
	for _, r := range s {
		if r > 127 {
			return "=?utf-8?B?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?="
		}
	}
	return s
}

// Send sends a plain-text email.  It dials SMTP manually rather than using
// smtp.SendMail because smtp.SendMail passes the dial address as the TLS
// ServerName.  When connecting to "localhost" while the server's certificate
// is for a different hostname this causes a TLS verification failure.
func (m *Mailer) Send(to, subject, body string) error {
	addr := m.host + ":" + m.port

	// Encode the body as quoted-printable.  This keeps every line to at most
	// 76 printable ASCII characters and encodes high-byte characters as "=XX",
	// meeting RFC 2822 line-length requirements without assuming the relay
	// supports 8BITMIME.
	var qpBuf bytes.Buffer
	qpw := quotedprintable.NewWriter(&qpBuf)
	fmt.Fprint(qpw, body)
	qpw.Close()

	msg := strings.Join([]string{
		"From: FrejaID Demo <" + m.from + ">",
		"To: " + to,
		"Subject: " + encodeHeader(subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: quoted-printable",
		"",
		qpBuf.String(),
	}, "\r\n")

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		return err
	}
	defer c.Close()

	// Upgrade to TLS if the server advertises STARTTLS.
	if ok, _ := c.Extension("STARTTLS"); ok {
		isLocal := m.host == "localhost" || m.host == "127.0.0.1"
		if err := c.StartTLS(&tls.Config{
			ServerName:         m.host,
			InsecureSkipVerify: isLocal, // safe: only skipped for loopback
		}); err != nil {
			return err
		}
	}

	// Authenticate if credentials are configured.
	if m.user != "" && m.pass != "" {
		if err := c.Auth(smtp.PlainAuth("", m.user, m.pass, m.host)); err != nil {
			return err
		}
	}

	if err := c.Mail(m.from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// ─────────────────────────────────────────────────────────────────────────────
// Typed email senders — one function per email template.
// This keeps all email copy in one file and makes it easy to add translations.
// ─────────────────────────────────────────────────────────────────────────────

// SendVerification sends the initial email verification link.
// Called when a user submits the registration form.
func (m *Mailer) SendVerification(to, name, link string) error {
	body := fmt.Sprintf(`Hi %s,

Please verify your email address to request access to FrejaID Demo.

Click this link (valid for 24 hours):
%s

If you did not request this, ignore this email.

— FrejaID Demo`, name, link)

	return m.Send(to, "Verify your email — FrejaID Demo", body)
}

// SendApproved tells a passkey user that their account has been approved and
// they can now log in.  Called by the admin approval flow.
func (m *Mailer) SendApproved(to, name, loginURL string) error {
	body := fmt.Sprintf(`Hi %s,

Your request to join FrejaID Demo has been approved.

Log in using your passkey at:
%s

Welcome aboard,
— FrejaID Demo`, name, loginURL)

	return m.Send(to, "You're in — FrejaID Demo", body)
}

// SendApprovedFreja tells a Freja eID user that their account has been
// approved.  Called by the admin approval flow for Freja registrations.
func (m *Mailer) SendApprovedFreja(to, name, loginURL string) error {
	body := fmt.Sprintf(`Hi %s,

Your request to join FrejaID Demo has been approved.

Log in using your Freja eID at:
%s

Welcome aboard,
— FrejaID Demo`, name, loginURL)

	return m.Send(to, "You're in — FrejaID Demo", body)
}

// SendEmailChange sends a confirmation link to a user's NEW email address
// when they request an email change.  The old address is unchanged until
// the link is clicked.
func (m *Mailer) SendEmailChange(to, name, link string) error {
	body := fmt.Sprintf(`Hi %s,

Someone (hopefully you) requested an email address change on FrejaID Demo.

Click this link to confirm your new email address (valid for 24 hours):
%s

If you did not request this, ignore this email — your address will not change.

— FrejaID Demo`, name, link)

	return m.Send(to, "Confirm your new email address — FrejaID Demo", body)
}

// SendPasskeyResetLink sends an approved passkey-reset link to the user.
// Called by the admin when they approve a credential reset request.
// The link leads to GET /auth/reset-passkey?token=… where the user registers
// a new passkey without needing any existing credential.
func (m *Mailer) SendPasskeyResetLink(to, name, link string) error {
	body := fmt.Sprintf(`Hi %s,

Your request for new credentials on FrejaID Demo has been approved.

Set up your new passkey using this link (valid for 48 hours):
%s

— FrejaID Demo`, name, link)

	return m.Send(to, "Set up your new passkey — FrejaID Demo", body)
}

// SendFrejaResetLink sends an approved Freja-reset link to the user.
// The link leads to GET /auth/reset-freja?token=…, which is Apache-protected:
// the user must authenticate with Freja eID before the Go app receives the
// request with the Freja identity in HTTP headers.
func (m *Mailer) SendFrejaResetLink(to, name, link string) error {
	body := fmt.Sprintf(`Hi %s,

Your request for new credentials on FrejaID Demo has been approved.

Link your Freja eID using this link (valid for 48 hours):
%s

— FrejaID Demo`, name, link)

	return m.Send(to, "Link your Freja eID — FrejaID Demo", body)
}

// SendAdminCredentialReset notifies all admins that a user has requested
// new credentials.  Admins review the request in the admin panel.
func (m *Mailer) SendAdminCredentialReset(to, userName, userEmail string) error {
	body := fmt.Sprintf(`A user has requested new credentials on FrejaID Demo.

Name:  %s
Email: %s

Review the request in the admin panel.

— FrejaID Demo`, userName, userEmail)

	return m.Send(to, "New credential reset request — FrejaID Demo", body)
}

// SendAdminAutoApproved notifies existing admins when a new admin account is
// automatically approved (because the email was in the ADMIN_EMAIL list).
// This is for audit purposes only; no action is required.
func (m *Mailer) SendAdminAutoApproved(to, newUserName, newUserEmail string) error {
	body := fmt.Sprintf(`A new admin account was automatically approved on FrejaID Demo.

Name:  %s
Email: %s

No action required — this notification is for your records.

— FrejaID Demo`, newUserName, newUserEmail)

	return m.Send(to, "New admin auto-approved — FrejaID Demo", body)
}
