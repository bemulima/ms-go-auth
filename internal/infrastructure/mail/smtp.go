package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

type SMTP struct{ Address, From string }

func (s *SMTP) Send(ctx context.Context, to, subject, body string) (sendErr error) {
	if strings.ContainsAny(to+s.From+subject, "\r\n") {
		return errors.New("invalid mail header")
	}
	host, _, err := net.SplitHostPort(s.Address)
	if err != nil {
		return errors.New("mail transport unavailable")
	}
	conn, err := net.DialTimeout("tcp", s.Address, 5*time.Second)
	if err != nil {
		return errors.New("mail transport unavailable")
	}
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return errors.New("mail transport unavailable")
	}
	quitSucceeded := false
	defer func() {
		if quitSucceeded {
			return
		}
		if closeErr := c.Close(); closeErr != nil && sendErr == nil {
			sendErr = errors.New("mail transport unavailable")
		}
	}()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err = c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return errors.New("mail transport unavailable")
		}
	} else if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("mail TLS required")
	}
	if err = c.Mail(s.From); err != nil {
		return errors.New("mail delivery failed")
	}
	if err = c.Rcpt(to); err != nil {
		return errors.New("mail delivery failed")
	}
	w, err := c.Data()
	if err != nil {
		return errors.New("mail delivery failed")
	}
	_, err = fmt.Fprintf(w, "From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n", s.From, to, subject, body)
	if err != nil {
		return errors.New("mail delivery failed")
	}
	if err = w.Close(); err != nil {
		return errors.New("mail delivery failed")
	}
	if err = c.Quit(); err != nil {
		return err
	}
	quitSucceeded = true
	return nil
}
