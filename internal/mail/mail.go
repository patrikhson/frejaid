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

type Mailer struct {
	host string
	port string
	from string
	user string
	pass string
}

func New(host, port, user, pass, from string) *Mailer {
	return &Mailer{host: host, port: port, from: from, user: user, pass: pass}
}

// encodeHeader encodes a header value with RFC 2047 base64 if it contains non-ASCII.
func encodeHeader(s string) string {
	for _, r := range s {
		if r > 127 {
			return "=?utf-8?B?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?="
		}
	}
	return s
}

func (m *Mailer) Send(to, subject, body string) error {
	addr := m.host + ":" + m.port

	// Encode body as quoted-printable so no raw 8-bit bytes are sent.
	// This avoids requiring SMTPUTF8 or 8BITMIME from the relay.
	var qpBuf bytes.Buffer
	qpw := quotedprintable.NewWriter(&qpBuf)
	fmt.Fprint(qpw, body)
	qpw.Close()

	msg := strings.Join([]string{
		"From: French 75 Tracker <" + m.from + ">",
		"To: " + to,
		"Subject: " + encodeHeader(subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: quoted-printable",
		"",
		qpBuf.String(),
	}, "\r\n")

	// Dial manually instead of using smtp.SendMail, which passes the dial
	// address as the TLS ServerName. Connecting to "localhost" while the
	// server's cert is for another hostname causes a cert verification failure.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		return err
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); ok {
		isLocal := m.host == "localhost" || m.host == "127.0.0.1"
		if err := c.StartTLS(&tls.Config{
			ServerName:         m.host,
			InsecureSkipVerify: isLocal,
		}); err != nil {
			return err
		}
	}

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

func (m *Mailer) SendVerification(to, name, link string) error {
	body := fmt.Sprintf(`Hi %s,

Please verify your email address to request access to French 75 Tracker.

Click this link (valid for 24 hours):
%s

If you did not request this, ignore this email.

— French 75 Tracker`, name, link)

	return m.Send(to, "Verify your email — French 75 Tracker", body)
}

func (m *Mailer) SendApproved(to, name, loginURL string) error {
	body := fmt.Sprintf(`Hi %s,

Your request to join French 75 Tracker has been approved.

Log in using your passkey at:
%s

Welcome aboard,
— French 75 Tracker`, name, loginURL)

	return m.Send(to, "You're in — French 75 Tracker", body)
}

func (m *Mailer) SendApprovedFreja(to, name, loginURL string) error {
	body := fmt.Sprintf(`Hi %s,

Your request to join French 75 Tracker has been approved.

Log in using your Freja eID at:
%s

Welcome aboard,
— French 75 Tracker`, name, loginURL)

	return m.Send(to, "You're in — French 75 Tracker", body)
}

func (m *Mailer) SendEmailChange(to, name, link string) error {
	body := fmt.Sprintf(`Hi %s,

Someone (hopefully you) requested an email address change on French 75 Tracker.

Click this link to confirm your new email address (valid for 24 hours):
%s

If you did not request this, ignore this email — your address will not change.

— French 75 Tracker`, name, link)

	return m.Send(to, "Confirm your new email address — French 75 Tracker", body)
}

func (m *Mailer) SendWelcome(to, name, link string) error {
	body := fmt.Sprintf(`Hi %s,

Your request to join French 75 Tracker has been approved.

Set up your passkey (Face ID, Touch ID, or security key) using this link:
%s

This link is valid for 48 hours. After setting up your passkey you can log in
at any time using your device.

Welcome aboard,
— French 75 Tracker`, name, link)

	return m.Send(to, "Welcome to French 75 Tracker — set up your passkey", body)
}
