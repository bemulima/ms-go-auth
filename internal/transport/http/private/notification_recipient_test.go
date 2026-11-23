package internalhttp

import (
	"context"
	"encoding/json"
	"github.com/example/auth-service/internal/usecase"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type notificationResolver struct {
	calls int
	err   error
}

func (f *notificationResolver) Resolve(ctx context.Context, id string) (usecase.NotificationRecipient, error) {
	f.calls++
	return usecase.NotificationRecipient{Schema: "auth.notification-recipient.v1", UserID: id, Email: "student@example.com", Verified: true, Revision: strings.Repeat("a", 64), CheckedAt: time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)}, f.err
}
func TestNotificationRecipientHTTPStrictPurposeBoundary(t *testing.T) {
	token := strings.Repeat("r", 40)
	valid := `{"schema":"auth.notification-recipient-request.v1","user_id":"11111111-1111-4111-8111-111111111111"}`
	for _, tc := range []struct {
		name, body string
		modify     func(*http.Request)
		status     int
	}{
		{"success", valid, nil, 200}, {"duplicate", strings.Replace(valid, `"user_id":`, `"user_id":"a","user_id":`, 1), nil, 400}, {"case", strings.Replace(valid, "user_id", "User_ID", 1), nil, 400}, {"null", strings.Replace(valid, `"11111111-1111-4111-8111-111111111111"`, `null`, 1), nil, 400}, {"role", strings.TrimSuffix(valid, "}") + `,"role":"admin"}`, nil, 400}, {"query", valid, func(r *http.Request) { r.URL.RawQuery = "x=1" }, 400}, {"encoding", valid, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, 400}, {"human jwt", valid, func(r *http.Request) { r.Header.Set("Authorization", "Bearer user-token") }, 401}, {"wrong token", valid, func(r *http.Request) { r.Header.Set("X-Notification-Recipient-Token", "wrong") }, 401}, {"duplicate token", valid, func(r *http.Request) { r.Header.Add("X-Notification-Recipient-Token", token) }, 401}, {"wrong method", valid, func(r *http.Request) { r.Method = "GET" }, 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &notificationResolver{}
			h, err := NewNotificationRecipientHandler(token, f)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", NotificationRecipientPath, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Notification-Recipient-Token", token)
			if tc.modify != nil {
				tc.modify(r)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			if tc.status != 200 && f.calls != 0 {
				t.Fatal("unauthorized owner read")
			}
			if tc.status == 200 {
				var out map[string]any
				if json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out) != 6 {
					t.Fatal("projection keys")
				}
			}
		})
	}
}
