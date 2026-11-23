package internalhttp

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/example/auth-service/internal/usecase"
)

const NotificationRecipientPath = "/internal/v1/notification/recipient"

type NotificationRecipientResolver interface {
	Resolve(context.Context, string) (usecase.NotificationRecipient, error)
}
type NotificationRecipientHandler struct {
	token    string
	resolver NotificationRecipientResolver
}

func NewNotificationRecipientHandler(token string, resolver NotificationRecipientResolver) (*NotificationRecipientHandler, error) {
	if len(token) < 32 || len(token) > 256 || strings.TrimSpace(token) != token || strings.ContainsAny(token, " \r\n\t\x00") || resolver == nil {
		return nil, usecase.ErrNotificationRecipientUnavailable
	}
	for _, c := range token {
		if c < 33 || c > 126 || c == ',' {
			return nil, usecase.ErrNotificationRecipientUnavailable
		}
	}
	return &NotificationRecipientHandler{token: token, resolver: resolver}, nil
}
func (h *NotificationRecipientHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if h == nil || h.resolver == nil {
		mentorHTTPFailure(w, 503, "unavailable")
		return
	}
	if r == nil || r.URL == nil || r.URL.Path != NotificationRecipientPath {
		mentorHTTPFailure(w, 404, "not_found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		mentorHTTPFailure(w, 405, "method_not_allowed")
		return
	}
	token, ok := mentorSingleHeader(r.Header, "X-Notification-Recipient-Token")
	if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(h.token)) != 1 || len(r.Header.Values("Authorization")) != 0 {
		mentorHTTPFailure(w, 401, "unauthenticated")
		return
	}
	content, single := mentorSingleHeader(r.Header, "Content-Type")
	if !single || !mentorJSONContentType(content) || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Fragment != "" || r.URL.User != nil || len(r.Header.Values("Content-Encoding")) != 0 || r.Body == nil || r.ContentLength > 1024 {
		mentorHTTPFailure(w, 400, "invalid_request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = r.Body.Close() })
	defer stop()
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1025))
	if err != nil || ctx.Err() != nil {
		mentorHTTPFailure(w, 503, "unavailable")
		return
	}
	id, ok := decodeNotificationRecipientRequest(raw)
	if !ok {
		mentorHTTPFailure(w, 400, "invalid_request")
		return
	}
	result, err := h.resolver.Resolve(ctx, id)
	if ctx.Err() != nil {
		mentorHTTPFailure(w, 503, "unavailable")
		return
	}
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrNotificationRecipientDenied):
			mentorHTTPFailure(w, 404, "recipient_unavailable")
		case errors.Is(err, usecase.ErrNotificationRecipientInvalid):
			mentorHTTPFailure(w, 400, "invalid_request")
		default:
			mentorHTTPFailure(w, 503, "unavailable")
		}
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}
func decodeNotificationRecipientRequest(raw []byte) (string, bool) {
	if len(raw) == 0 || len(raw) > 1024 || !validMentorHTTPJSONEncoding(raw) {
		return "", false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return "", false
	}
	fields := map[string]string{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || (name != "schema" && name != "user_id") {
			return "", false
		}
		if _, exists := fields[name]; exists {
			return "", false
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || len(value) == 0 || value[0] != '"' {
			return "", false
		}
		var text string
		if json.Unmarshal(value, &text) != nil {
			return "", false
		}
		fields[name] = text
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return "", false
	}
	if _, err := d.Token(); err != io.EOF {
		return "", false
	}
	return fields["user_id"], len(fields) == 2 && fields["schema"] == "auth.notification-recipient-request.v1" && fields["user_id"] != ""
}
