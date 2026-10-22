package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// httpClient is used for chat and webhook delivery. These go to operator-
// configured endpoints, not scan targets, so they bypass the scan guard.
var httpClient = &http.Client{Timeout: 15 * time.Second}

func postJSON(ctx context.Context, url string, body []byte, header http.Header) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Scout-Alerts/1")
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("endpoint returned %s", resp.Status)
	}
	return nil
}

// Slack posts to a Slack incoming webhook.
type Slack struct {
	WebhookURL string `json:"webhook_url" yaml:"webhook_url"`
}

func (Slack) Name() string { return "slack" }

func (s Slack) Notify(ctx context.Context, a Alert) error {
	body, err := json.Marshal(map[string]string{"text": a.Text()})
	if err != nil {
		return err
	}
	return postJSON(ctx, s.WebhookURL, body, nil)
}

// Discord posts to a Discord webhook. Messages are capped at 2000 characters.
type Discord struct {
	WebhookURL string `json:"webhook_url" yaml:"webhook_url"`
}

func (Discord) Name() string { return "discord" }

func (d Discord) Notify(ctx context.Context, a Alert) error {
	text := a.Text()
	if r := []rune(text); len(r) > 2000 {
		text = string(r[:1997]) + "…"
	}
	body, err := json.Marshal(map[string]string{"content": text})
	if err != nil {
		return err
	}
	return postJSON(ctx, d.WebhookURL, body, nil)
}

// Webhook posts the alert as JSON, signed with HMAC-SHA256 so the receiver
// can verify it came from Scout:
//
//	X-Scout-Timestamp: <unix seconds>
//	X-Scout-Signature: sha256=<hex HMAC(secret, timestamp + "." + body)>
type Webhook struct {
	URL    string `json:"url" yaml:"url"`
	Secret string `json:"-" yaml:"secret"`
}

func (Webhook) Name() string { return "webhook" }

// WebhookPayload is the JSON body of a webhook alert.
type WebhookPayload struct {
	Event string `json:"event"`
	Alert
}

func (w Webhook) Notify(ctx context.Context, a Alert) error {
	body, err := json.Marshal(WebhookPayload{Event: "scan.alert", Alert: a})
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	h := http.Header{}
	h.Set("X-Scout-Timestamp", ts)
	h.Set("X-Scout-Signature", "sha256="+Sign(w.Secret, ts, body))
	return postJSON(ctx, w.URL, body, h)
}

// Sign computes the webhook signature for a timestamp and body.
func Sign(secret, timestamp string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(timestamp))
	m.Write([]byte("."))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// VerifyWebhook checks a received webhook's signature and rejects
// timestamps older than maxAge, for receivers written in Go.
func VerifyWebhook(secret, timestamp, signature string, body []byte, now time.Time, maxAge time.Duration) bool {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	if d := now.Sub(time.Unix(ts, 0)); d > maxAge || d < -maxAge {
		return false
	}
	want := "sha256=" + Sign(secret, timestamp, body)
	return hmac.Equal([]byte(want), []byte(signature))
}

// Email sends alerts over SMTP. smtp.SendMail upgrades to STARTTLS when the
// server offers it; implicit-TLS port 465 is not supported.
type Email struct {
	Host     string   `json:"host" yaml:"host"`
	Port     int      `json:"port" yaml:"port"`
	Username string   `json:"username,omitempty" yaml:"username"`
	Password string   `json:"-" yaml:"password"`
	From     string   `json:"from" yaml:"from"`
	To       []string `json:"to" yaml:"to"`
}

func (Email) Name() string { return "email" }

// sendMail is swapped in tests.
var sendMail = smtp.SendMail

func (e Email) Notify(_ context.Context, a Alert) error {
	if len(e.To) == 0 {
		return fmt.Errorf("email: no recipients")
	}
	port := e.Port
	if port == 0 {
		port = 587
	}
	var auth smtp.Auth
	if e.Username != "" {
		auth = smtp.PlainAuth("", e.Username, e.Password, e.Host)
	}
	return sendMail(net.JoinHostPort(e.Host, strconv.Itoa(port)), auth, e.From, e.To, e.message(a))
}

// message builds the RFC 5322 message. Header values come from config and
// scanned data, so CR/LF are stripped to prevent header injection.
func (e Email) message(a Alert) []byte {
	clean := func(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", clean(e.From))
	fmt.Fprintf(&b, "To: %s\r\n", clean(strings.Join(e.To, ", ")))
	fmt.Fprintf(&b, "Subject: %s\r\n", clean(a.Summary()))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString(strings.ReplaceAll(a.Text(), "\n", "\r\n"))
	return b.Bytes()
}
