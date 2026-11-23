package repo

import (
	"context"
	"errors"
	"time"

	"github.com/example/auth-service/internal/domain"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type mcpExternalClientConsentRepo struct{ db *gorm.DB }

var _ domain.MCPExternalClientConsentReader = (*mcpExternalClientConsentRepo)(nil)
var _ domain.MCPExternalConsentRevoker = (*mcpExternalClientConsentRepo)(nil)

func NewMCPExternalClientConsentRepository(db *gorm.DB) domain.MCPExternalClientConsentReader {
	return &mcpExternalClientConsentRepo{db: db}
}

func NewMCPExternalConsentRevoker(db *gorm.DB) domain.MCPExternalConsentRevoker {
	return &mcpExternalClientConsentRepo{db: db}
}

// ReadMCPExternalClientConsent performs independent client and subject-bound
// consent reads. No client-provided redirect or scopes reach the SQL lookup.
func (r *mcpExternalClientConsentRepo) ReadMCPExternalClientConsent(
	ctx context.Context, studentID, clientID, resource string, now time.Time,
) (*domain.MCPExternalClientRegistration, *domain.MCPExternalStoredConsent, error) {
	if r == nil || r.db == nil || ctx == nil || ctx.Err() != nil ||
		!mcpCanonicalUUID.MatchString(studentID) || clientID == "" || len(clientID) > 256 ||
		resource == "" || len(resource) > 2048 || now.IsZero() {
		return nil, nil, errors.New("MCP client/consent unavailable")
	}
	var client struct {
		ClientID      string `gorm:"column:client_id"`
		RedirectsJSON string `gorm:"column:redirects_json"`
		ScopesJSON    string `gorm:"column:scopes_json"`
	}
	priv := r.db.WithContext(ctx).Session(&gorm.Session{Logger: logger.Discard})
	err := priv.Raw(`
		SELECT client_id, array_to_json(redirect_uris)::text AS redirects_json,
		       array_to_json(allowed_scopes)::text AS scopes_json
		FROM auth_mcp_client
		WHERE client_id = ? AND resource_uri = ? AND disabled_at IS NULL
		LIMIT 1`, clientID, resource).Scan(&client).Error
	if err != nil || client.ClientID != clientID {
		return nil, nil, errors.New("MCP client/consent unavailable")
	}
	redirects, ok := decodeMCPExternalRedirectURIs(client.RedirectsJSON)
	if !ok || len(redirects) == 0 {
		return nil, nil, errors.New("MCP client/consent unavailable")
	}
	scopes, ok := decodeMCPExternalStoredScopes(client.ScopesJSON)
	if !ok || len(scopes) == 0 {
		return nil, nil, errors.New("MCP client/consent unavailable")
	}
	var consent struct {
		ID         string    `gorm:"column:id"`
		ScopesJSON string    `gorm:"column:scopes_json"`
		ExpiresAt  time.Time `gorm:"column:expires_at"`
	}
	err = priv.Raw(`
		SELECT id::text AS id, array_to_json(granted_scopes)::text AS scopes_json, expires_at
		FROM auth_mcp_consent
		WHERE student_id = ?::uuid AND client_id = ? AND resource_uri = ?
		  AND revoked_at IS NULL AND expires_at > ?
		ORDER BY expires_at DESC, id DESC
		LIMIT 1`, studentID, clientID, resource, now.UTC()).Scan(&consent).Error
	if err != nil || consent.ID == "" || !consent.ExpiresAt.After(now) {
		return nil, nil, errors.New("MCP client/consent unavailable")
	}
	consentScopes, ok := decodeMCPExternalStoredScopes(consent.ScopesJSON)
	if !ok || len(consentScopes) == 0 {
		return nil, nil, errors.New("MCP client/consent unavailable")
	}
	return &domain.MCPExternalClientRegistration{
			ClientID: clientID, RedirectURIs: redirects, AllowedScopes: scopes,
		}, &domain.MCPExternalStoredConsent{
			ID: consent.ID, StudentID: studentID, ClientID: clientID,
			ResourceURI: resource, Scopes: consentScopes, ExpiresAt: consent.ExpiresAt,
		}, nil
}

// RevokeMCPExternalConsent atomically disables all current consents for the
// authenticated Student/client/resource tuple, including old duplicate rows.
// No prompt/client-supplied subject can reach this query through Auth HTTP.
func (r *mcpExternalClientConsentRepo) RevokeMCPExternalConsent(
	ctx context.Context, studentID, clientID, resource string,
) error {
	if r == nil || r.db == nil || ctx == nil || ctx.Err() != nil ||
		!mcpCanonicalUUID.MatchString(studentID) || clientID == "" || len(clientID) > 256 ||
		resource == "" || len(resource) > 2048 {
		return errors.New("MCP consent revocation unavailable")
	}
	result := r.db.WithContext(ctx).Session(&gorm.Session{Logger: logger.Discard}).Exec(`
		UPDATE auth_mcp_consent
		SET revoked_at = clock_timestamp()
		WHERE student_id = CAST(? AS uuid) AND client_id = ? AND resource_uri = ?
		  AND revoked_at IS NULL`, studentID, clientID, resource)
	if result.Error != nil || ctx.Err() != nil {
		return errors.New("MCP consent revocation unavailable")
	}
	return nil
}
