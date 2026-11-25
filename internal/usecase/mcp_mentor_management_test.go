package usecase

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/example/auth-service/internal/domain"
	"strings"
	"testing"
)

func TestMCPMentorManagementUsesExactEnabledScope(t *testing.T) {
	for _, scope := range []string{"mentor:offers:publish", "mentor:cohorts:respond", "mentor:students:feedback", "mentor:dialogs:write", "mentor:students:assign", "mentor:cohorts:assign"} {
		t.Run(scope, func(t *testing.T) { testMCPMentorManagementScope(t, scope) })
	}
}

func testMCPMentorManagementScope(t *testing.T, scope string) {
	t.Helper()
	oauth, store, authority, request, verifier, _, _ := mentorOAuthFixture(t)
	ctx := context.Background()
	request.Scope = scope
	store.client.Scopes = append(store.client.Scopes, request.Scope)
	oauth.WorkspaceReadEnabled = true
	if _, err := oauth.Preview(ctx, request, mentorOAuthActor); err != domain.ErrMCPMentorDenied {
		t.Fatalf("read feature admitted unrelated management authority: %v", err)
	}
	oauth.ManagementEnabled = true
	token, err := oauth.Exchange(ctx, mentorOAuthExchangeRequest(request, mentorOAuthCode(t, oauth, request), verifier))
	if err != nil || token.Scope != request.Scope || authority.lastScope != request.Scope {
		t.Fatalf("management authority reached wrong RBAC scope or token: %v", err)
	}
	grant, err := oauth.Verify(ctx, token.AccessToken, oauth.Resource, oauth.now())
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(strings.Split(grant.OwnerProof, ".")[1])
	var claims map[string]any
	if err != nil || json.Unmarshal(claimsJSON, &claims) != nil || claims["scope"] != request.Scope || claims["purpose"] != domain.MCPMentorManagementPurpose {
		t.Fatal("management proof did not bind the owner purpose")
	}
	oauth.ManagementEnabled = false
	if _, err := oauth.Verify(ctx, token.AccessToken, oauth.Resource, oauth.now()); err != domain.ErrMCPMentorDenied {
		t.Fatalf("management access survived switch-off: %v", err)
	}
}
