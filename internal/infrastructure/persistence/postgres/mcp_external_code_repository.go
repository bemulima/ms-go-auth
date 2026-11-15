package repo

import (
	"context"
	"strings"
	"time"

	"github.com/example/auth-service/internal/domain"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type mcpExternalCodeRepo struct{ db *gorm.DB }

var _ domain.MCPExternalCodeRepository = (*mcpExternalCodeRepo)(nil)

func NewMCPExternalCodeRepository(db *gorm.DB) domain.MCPExternalCodeRepository {
	return &mcpExternalCodeRepo{db: db}
}

// These operations deliberately suppress GORM's SQL logging, including bound
// code hashes, subjects and authorization inputs, regardless of debug mode.
func (r *mcpExternalCodeRepo) privateDB(ctx context.Context) *gorm.DB {
	return r.db.WithContext(ctx).Session(&gorm.Session{Logger: logger.Discard})
}

// CreateMCPExternalCode rechecks persisted Auth-owned consent and registered
// client metadata at write time. A prompt-supplied consent/client cannot mint
// a code, even when a caller miswires an earlier use-case read.
func (r *mcpExternalCodeRepo) CreateMCPExternalCode(ctx context.Context, code *domain.MCPExternalAuthorizationCode) error {
	if code == nil || code.CodeHash == "" || code.StudentID == "" || code.ConsentID == "" ||
		code.ClientID == "" || code.RedirectURI == "" || code.ResourceURI == "" ||
		code.CodeChallenge == "" || len(code.Scopes) == 0 || code.ExpiresAt.IsZero() {
		return domain.ErrNotFound
	}
	scopeText := strings.Join(code.Scopes, " ")
	result := r.privateDB(ctx).Exec(`
		INSERT INTO auth_mcp_authorization_code
			(code_hash, student_id, client_id, consent_id, redirect_uri,
			 resource_uri, pkce_challenge, scopes, expires_at)
		SELECT ?, consent.student_id, consent.client_id, consent.id, ?,
		       consent.resource_uri, ?, string_to_array(?, ' '), ?
		FROM auth_mcp_consent AS consent
		JOIN auth_mcp_client AS client ON client.client_id = consent.client_id
		WHERE consent.id = ? AND consent.student_id = ?
		  AND consent.client_id = ? AND consent.resource_uri = ?
		  AND client.resource_uri = consent.resource_uri
		  AND client.disabled_at IS NULL
		  AND consent.revoked_at IS NULL
		  AND consent.expires_at > clock_timestamp()
		  AND consent.expires_at >= ?
		  AND ? = ANY(client.redirect_uris)
		  AND consent.granted_scopes @> string_to_array(?, ' ')
		  AND client.allowed_scopes @> string_to_array(?, ' ')
	`, code.CodeHash, code.RedirectURI, code.CodeChallenge, scopeText, code.ExpiresAt,
		code.ConsentID, code.StudentID, code.ClientID, code.ResourceURI, code.ExpiresAt,
		code.RedirectURI, scopeText, scopeText)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return domain.ErrNotFound
	}
	return nil
}

type mcpExternalCodeRow struct {
	CodeHash      string    `gorm:"column:code_hash"`
	StudentID     string    `gorm:"column:student_id"`
	ClientID      string    `gorm:"column:client_id"`
	ConsentID     string    `gorm:"column:consent_id"`
	RedirectURI   string    `gorm:"column:redirect_uri"`
	ResourceURI   string    `gorm:"column:resource_uri"`
	CodeChallenge string    `gorm:"column:code_challenge"`
	Scope         string    `gorm:"column:scope"`
	ExpiresAt     time.Time `gorm:"column:expires_at"`
}

// ConsumeMCPExternalCode is a single SQL conditional UPDATE ... RETURNING.
// PostgreSQL serializes concurrent updates of the same code row: at most one
// reader receives it. It also checks revocation, expiry and current scopes.
func (r *mcpExternalCodeRepo) ConsumeMCPExternalCode(
	ctx context.Context, hash, clientID, redirectURI, resourceURI string, now time.Time,
) (*domain.MCPExternalAuthorizationCode, error) {
	if hash == "" || clientID == "" || redirectURI == "" || resourceURI == "" || now.IsZero() {
		return nil, domain.ErrNotFound
	}
	var row mcpExternalCodeRow
	result := r.privateDB(ctx).Raw(`
		UPDATE auth_mcp_authorization_code AS code
		SET consumed_at = clock_timestamp()
		FROM auth_mcp_consent AS consent, auth_mcp_client AS client
		WHERE code.code_hash = ? AND code.client_id = ?
		  AND code.redirect_uri = ? AND code.resource_uri = ?
		  AND code.consumed_at IS NULL
		  AND code.expires_at > ? AND code.expires_at > clock_timestamp()
		  AND consent.id = code.consent_id
		  AND consent.student_id = code.student_id
		  AND consent.client_id = code.client_id
		  AND consent.resource_uri = code.resource_uri
		  AND consent.revoked_at IS NULL
		  AND consent.expires_at > ? AND consent.expires_at > clock_timestamp()
		  AND client.client_id = code.client_id
		  AND client.resource_uri = code.resource_uri
		  AND client.disabled_at IS NULL
		  AND code.redirect_uri = ANY(client.redirect_uris)
		  AND consent.granted_scopes @> code.scopes
		  AND client.allowed_scopes @> code.scopes
		RETURNING code.code_hash, code.student_id, code.client_id,
		          code.consent_id, code.redirect_uri, code.resource_uri,
		          code.pkce_challenge AS code_challenge,
		          array_to_string(code.scopes, ' ') AS scope,
		          code.expires_at
	`, hash, clientID, redirectURI, resourceURI, now, now).Scan(&row)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected != 1 || row.CodeHash == "" {
		return nil, domain.ErrNotFound
	}
	return &domain.MCPExternalAuthorizationCode{
		CodeHash:      row.CodeHash,
		StudentID:     row.StudentID,
		ClientID:      row.ClientID,
		ConsentID:     row.ConsentID,
		RedirectURI:   row.RedirectURI,
		ResourceURI:   row.ResourceURI,
		CodeChallenge: row.CodeChallenge,
		Scopes:        strings.Split(row.Scope, " "),
		ExpiresAt:     row.ExpiresAt,
	}, nil
}
