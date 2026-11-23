package repo

import (
	"context"
	"encoding/json"
	"regexp"
	"time"

	"github.com/example/auth-service/internal/domain"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type mcpExternalAuthGrantRepo struct{ db *gorm.DB }

var _ domain.MCPExternalAuthGrantReader = (*mcpExternalAuthGrantRepo)(nil)

var mcpCanonicalUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// NewMCPExternalAuthGrantRepository supplies only Auth-owned persisted state.
// It does NOT implement the higher-level MCPExternalTokenGrantReadback port:
// live signed RBAC and authorization-code consumption are separate obligations.
func NewMCPExternalAuthGrantRepository(db *gorm.DB) domain.MCPExternalAuthGrantReader {
	return &mcpExternalAuthGrantRepo{db: db}
}

type mcpExternalAuthGrantRow struct {
	StudentID         string    `gorm:"column:student_id"`
	ClientID          string    `gorm:"column:client_id"`
	ConsentID         string    `gorm:"column:consent_id"`
	ResourceURI       string    `gorm:"column:resource_uri"`
	ConsentExpiresAt  time.Time `gorm:"column:consent_expires_at"`
	ClientScopesJSON  string    `gorm:"column:client_scopes_json"`
	ConsentScopesJSON string    `gorm:"column:consent_scopes_json"`
}

// ReadMCPExternalAuthGrant rechecks the current Auth account, approved client,
// consent and scopes after an OAuth code was consumed. It must not return
// unauthenticated RBAC decisions, a JWT, or an authorization to sign one.
// PostgreSQL clock_timestamp is checked independently of the supplied clock;
// all SQL input and returned errors are deliberately kept out of log output.
func (r *mcpExternalAuthGrantRepo) ReadMCPExternalAuthGrant(
	ctx context.Context, studentID, clientID, consentID, resourceURI string, now time.Time,
) (*domain.MCPExternalAuthGrantSnapshot, error) {
	if r == nil || r.db == nil || ctx == nil || ctx.Err() != nil || now.IsZero() ||
		!mcpCanonicalUUID.MatchString(studentID) || !mcpCanonicalUUID.MatchString(consentID) ||
		clientID == "" || len(clientID) > 2048 || resourceURI == "" || len(resourceURI) > 2048 {
		return nil, domain.ErrNotFound
	}
	var row mcpExternalAuthGrantRow
	result := r.db.WithContext(ctx).Session(&gorm.Session{Logger: logger.Discard}).Raw(`
		SELECT consent.student_id::text AS student_id,
		       consent.client_id, consent.id::text AS consent_id,
		       consent.resource_uri, consent.expires_at AS consent_expires_at,
		       array_to_json(client.allowed_scopes)::text AS client_scopes_json,
		       array_to_json(consent.granted_scopes)::text AS consent_scopes_json
		FROM auth_mcp_consent AS consent
		JOIN auth_mcp_client AS client ON client.client_id = consent.client_id
		  AND client.resource_uri = consent.resource_uri
		JOIN auth_user AS account ON account.id = consent.student_id
		WHERE consent.id = CAST(? AS uuid) AND consent.student_id = CAST(? AS uuid)
		  AND consent.client_id = ? AND consent.resource_uri = ?
		  AND consent.revoked_at IS NULL AND client.disabled_at IS NULL
		  AND consent.expires_at > ? AND consent.expires_at > clock_timestamp()
		  AND account.email_verified = true
		  AND NOT EXISTS (
		      SELECT 1 FROM auth_signup_completion AS signup
		      WHERE signup.principal_id = account.id AND signup.state <> 'completed'
		  )
		  AND octet_length(array_to_json(client.allowed_scopes)::text) <= 8192
		  AND octet_length(array_to_json(consent.granted_scopes)::text) <= 8192
	`, consentID, studentID, clientID, resourceURI, now.UTC()).Scan(&row)
	if result.Error != nil || result.RowsAffected != 1 || ctx.Err() != nil ||
		row.StudentID != studentID || row.ClientID != clientID ||
		row.ConsentID != consentID || row.ResourceURI != resourceURI ||
		!row.ConsentExpiresAt.After(now) {
		return nil, domain.ErrNotFound
	}
	clientScopes, ok := decodeMCPExternalStoredScopes(row.ClientScopesJSON)
	if !ok {
		return nil, domain.ErrNotFound
	}
	consentScopes, ok := decodeMCPExternalStoredScopes(row.ConsentScopesJSON)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return &domain.MCPExternalAuthGrantSnapshot{
		StudentID:        row.StudentID,
		ClientID:         row.ClientID,
		ConsentID:        row.ConsentID,
		ResourceURI:      row.ResourceURI,
		ConsentExpiresAt: row.ConsentExpiresAt.UTC(),
		ClientScopes:     clientScopes,
		ConsentScopes:    consentScopes,
	}, nil
}

// Text-array elements are decoded through PostgreSQL JSON conversion to
// preserve exact scope boundaries. Do not split a space-joined SQL projection.
func decodeMCPExternalStoredScopes(encoded string) ([]string, bool) {
	if len(encoded) == 0 || len(encoded) > 8192 {
		return nil, false
	}
	var scopes []string
	if err := json.Unmarshal([]byte(encoded), &scopes); err != nil || len(scopes) == 0 || len(scopes) > 32 {
		return nil, false
	}
	seen := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		if len(scope) == 0 || len(scope) > 128 || seen[scope] {
			return nil, false
		}
		for _, ch := range scope {
			if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' ||
				ch >= '0' && ch <= '9' || ch == ':' || ch == '-' ||
				ch == '_' || ch == '.' {
				continue
			}
			return nil, false
		}
		seen[scope] = true
	}
	return scopes, true
}
