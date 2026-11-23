package repo

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
)

func TestMCPExternalAuthGrantStoredScopesStrictJSON(t *testing.T) {
	got, ok := decodeMCPExternalStoredScopes(`["courses:read","tasks:read"]`)
	if !ok || !reflect.DeepEqual(got, []string{"courses:read", "tasks:read"}) {
		t.Fatalf("valid persisted scope list rejected: %q", got)
	}
	for _, tc := range []struct {
		name, value string
	}{
		{"empty", ""},
		{"null", `null`},
		{"nonarray", `{"scope":"courses:read"}`},
		{"emptyarray", `[]`},
		{"scalar", `[42]`},
		{"duplicate", `["courses:read","courses:read"]`},
		{"wildcard", `["*"]`},
		{"embedded-space", `["courses:read tasks:write"]`},
		{"newline", `["courses:read\n"]`},
		{"unicode", `["курсы:читать"]`},
		{"overlong-scope", `["` + strings.Repeat("a", 129) + `"]`},
		{"large-json", `["` + strings.Repeat("a", 8193) + `"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := decodeMCPExternalStoredScopes(tc.value)
			if ok || got != nil {
				t.Fatalf("invalid scopes accepted: %q", got)
			}
		})
	}
}

func TestMCPExternalAuthGrantReaderDeniesWithoutDatabase(t *testing.T) {
	r := NewMCPExternalAuthGrantRepository(nil)
	ctx := context.Background()
	const student = "00000000-0000-4000-8000-000000000001"
	const consent = "00000000-0000-4000-8000-000000000002"
	resource := "https://mcp.example.test/mcp"
	now := time.Now().UTC()
	for _, tc := range []struct {
		name, user, consent, client, resource string
	}{
		{"no-db", student, consent, "client", resource},
		{"malformed-student", "not-a-uuid", consent, "client", resource},
		{"malformed-consent", student, "not-a-uuid", "client", resource},
		{"missing-client", student, consent, "", resource},
		{"missing-resource", student, consent, "client", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := r.ReadMCPExternalAuthGrant(ctx, tc.user, tc.client, tc.consent, tc.resource, now)
			if got != nil || !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("reader accepted invalid lookup: %+v %v", got, err)
			}
		})
	}
}
