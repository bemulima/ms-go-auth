package repo

import (
	"context"
	"encoding/hex"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/example/auth-service/internal/domain"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type mcpMentorStore struct{ db *gorm.DB }

func NewMCPMentorStore(db *gorm.DB) domain.MCPMentorStore {
	if db == nil {
		return &mcpMentorStore{}
	}
	return &mcpMentorStore{db: db.Session(&gorm.Session{Logger: logger.Discard})}
}
func mcpMentorUUID(v string) bool {
	return mcpCanonicalUUID.MatchString(v) && v != "00000000-0000-0000-0000-000000000000"
}
func mcpMentorBinding(subject, client, resource string) bool {
	if !mcpMentorUUID(subject) || len(client) == 0 || len(client) > 256 || len(resource) == 0 || len(resource) > 2048 {
		return false
	}
	for _, b := range []byte(client) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

const mcpMentorAccountSQL = `account.email_verified=true AND NOT EXISTS(SELECT 1 FROM public.auth_signup_completion signup WHERE signup.principal_id=account.id AND signup.state<>'completed')`

func (r *mcpMentorStore) Client(ctx context.Context, subject, client, resource string) (*domain.MCPMentorClient, error) {
	if r == nil || r.db == nil || ctx == nil || ctx.Err() != nil || !mcpMentorBinding(subject, client, resource) {
		return nil, domain.ErrMCPMentorUnavailable
	}
	var row struct{ ClientID, DisplayName, RedirectsJSON, ScopesJSON string }
	result := r.db.WithContext(ctx).Raw(`SELECT client.client_id,client.display_name,array_to_json(client.redirect_uris)::text AS redirects_json,array_to_json(client.allowed_scopes)::text AS scopes_json
		FROM public.auth_mcp_mentor_client client JOIN public.auth_user account ON account.id=CAST(? AS uuid)
		WHERE client.client_id=? AND client.resource_uri=? AND client.disabled_at IS NULL AND `+mcpMentorAccountSQL+`
		AND octet_length(array_to_json(client.redirect_uris)::text)<=8192`, subject, client, resource).Scan(&row)
	if result.Error != nil || ctx.Err() != nil {
		return nil, domain.ErrMCPMentorUnavailable
	}
	if result.RowsAffected != 1 {
		return nil, domain.ErrMCPMentorDenied
	}
	redirects, ok := decodeMCPExternalRedirectURIs(row.RedirectsJSON)
	scopes, valid := decodeMCPExternalStoredScopes(row.ScopesJSON)
	if row.ClientID != client || !ok || !valid || len(scopes) > 6+len(domain.MCPMentorWorkspaceReadScopes())+len(domain.MCPMentorAuthoringScopes())+len(domain.MCPMentorManagementScopes()) || len(row.DisplayName) == 0 || len(row.DisplayName) > 160 || !utf8.ValidString(row.DisplayName) || strings.ContainsFunc(row.DisplayName, unicode.IsControl) {
		return nil, domain.ErrMCPMentorUnavailable
	}
	for _, scope := range scopes {
		if !domain.ValidMCPMentorScope(scope) {
			return nil, domain.ErrMCPMentorUnavailable
		}
	}
	return &domain.MCPMentorClient{ID: client, Name: row.DisplayName, RedirectURIs: redirects, Scopes: scopes}, nil
}

type mcpMentorConsentRow struct {
	ID, MentorID, ClientID, ResourceURI, Scope string
	ExpiresAt                                  time.Time
}

func (r *mcpMentorStore) Consent(ctx context.Context, subject, client, resource, id string, now time.Time) (*domain.MCPMentorConsent, error) {
	if r == nil || r.db == nil || ctx == nil || ctx.Err() != nil || !mcpMentorBinding(subject, client, resource) || (id != "" && !mcpMentorUUID(id)) || now.IsZero() {
		return nil, domain.ErrMCPMentorUnavailable
	}
	var rows []mcpMentorConsentRow
	query := `SELECT consent.id::text,consent.mentor_id::text,consent.client_id,consent.resource_uri,consent.granted_scopes[1] AS scope,consent.expires_at
		FROM public.auth_mcp_mentor_consent consent JOIN public.auth_mcp_mentor_client client ON client.client_id=consent.client_id AND client.resource_uri=consent.resource_uri
		JOIN public.auth_user account ON account.id=consent.mentor_id
		WHERE consent.mentor_id=CAST(? AS uuid) AND consent.client_id=? AND consent.resource_uri=?
		AND consent.revoked_at IS NULL AND client.disabled_at IS NULL AND consent.expires_at>? AND consent.expires_at>clock_timestamp()
		AND cardinality(consent.granted_scopes)=1 AND consent.granted_scopes<@client.allowed_scopes AND ` + mcpMentorAccountSQL
	args := []any{subject, client, resource, now.UTC()}
	if id != "" {
		query += ` AND consent.id=CAST(? AS uuid)`
		args = append(args, id)
	}
	query += ` LIMIT 2`
	result := r.db.WithContext(ctx).Raw(query, args...).Scan(&rows)
	if result.Error != nil || ctx.Err() != nil || len(rows) > 1 {
		return nil, domain.ErrMCPMentorUnavailable
	}
	if len(rows) == 0 {
		return nil, domain.ErrNotFound
	}
	c := rows[0]
	if !mcpMentorUUID(c.ID) || !domain.ValidMCPMentorScope(c.Scope) || c.MentorID != subject || c.ClientID != client || c.ResourceURI != resource || (id != "" && c.ID != id) || !c.ExpiresAt.After(now) {
		return nil, domain.ErrMCPMentorUnavailable
	}
	return &domain.MCPMentorConsent{ID: c.ID, MentorID: subject, ClientID: client, Resource: resource, Scope: c.Scope, ExpiresAt: c.ExpiresAt.UTC()}, nil
}
func mcpMentorLockAccount(tx *gorm.DB, subject string) error {
	var row struct{ ID string }
	result := tx.Raw(`SELECT account.id::text FROM public.auth_user account WHERE account.id=CAST(? AS uuid) AND `+mcpMentorAccountSQL+` FOR UPDATE`, subject).Scan(&row)
	if result.Error != nil {
		return domain.ErrMCPMentorUnavailable
	}
	if result.RowsAffected != 1 || row.ID != subject {
		return domain.ErrMCPMentorDenied
	}
	return nil
}
func (r *mcpMentorStore) CreateGrant(ctx context.Context, consent domain.MCPMentorConsent, code domain.MCPMentorCode, now time.Time) error {
	hash, err := hex.DecodeString(code.Hash)
	if r == nil || r.db == nil || ctx == nil || ctx.Err() != nil || !mcpMentorBinding(consent.MentorID, consent.ClientID, consent.Resource) || !mcpMentorUUID(consent.ID) || code.MentorID != consent.MentorID || code.ClientID != consent.ClientID || code.Resource != consent.Resource || code.ConsentID != consent.ID || !domain.ValidMCPMentorScope(consent.Scope) || code.Scope != consent.Scope || err != nil || len(hash) != 32 || code.Hash != strings.ToLower(code.Hash) || len(code.Challenge) != 43 || len(code.RedirectURI) > 2048 || now.IsZero() || !consent.ExpiresAt.After(now) || consent.ExpiresAt.After(now.Add(24*time.Hour)) || !code.ExpiresAt.After(now) || code.ExpiresAt.After(now.Add(5*time.Minute)) || code.ExpiresAt.After(consent.ExpiresAt) {
		return domain.ErrMCPMentorUnavailable
	}
	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := mcpMentorLockAccount(tx, consent.MentorID); err != nil {
			return err
		}
		var client struct{ ClientID string }
		result := tx.Raw(`SELECT client_id FROM public.auth_mcp_mentor_client WHERE client_id=? AND resource_uri=? AND disabled_at IS NULL AND CAST(? AS text)=ANY(allowed_scopes) AND ?=ANY(redirect_uris) FOR SHARE`, consent.ClientID, consent.Resource, consent.Scope, code.RedirectURI).Scan(&client)
		if result.Error != nil {
			return domain.ErrMCPMentorUnavailable
		}
		if result.RowsAffected != 1 || client.ClientID != consent.ClientID {
			return domain.ErrMCPMentorDenied
		}
		if err := tx.Exec(`UPDATE public.auth_mcp_mentor_consent SET revoked_at=clock_timestamp() WHERE mentor_id=CAST(? AS uuid) AND client_id=? AND resource_uri=? AND revoked_at IS NULL`, consent.MentorID, consent.ClientID, consent.Resource).Error; err != nil {
			return domain.ErrMCPMentorUnavailable
		}
		result = tx.Exec(`INSERT INTO public.auth_mcp_mentor_consent(id,mentor_id,client_id,resource_uri,granted_scopes,expires_at) VALUES(CAST(? AS uuid),CAST(? AS uuid),?,?,ARRAY[CAST(? AS text)],?)`, consent.ID, consent.MentorID, consent.ClientID, consent.Resource, consent.Scope, consent.ExpiresAt.UTC())
		if result.Error != nil || result.RowsAffected != 1 {
			return domain.ErrMCPMentorUnavailable
		}
		result = tx.Exec(`INSERT INTO public.auth_mcp_mentor_code(code_hash,mentor_id,client_id,consent_id,resource_uri,redirect_uri,pkce_challenge,expires_at) VALUES(?,CAST(? AS uuid),?,CAST(? AS uuid),?,?,?,?)`, code.Hash, code.MentorID, code.ClientID, code.ConsentID, code.Resource, code.RedirectURI, code.Challenge, code.ExpiresAt.UTC())
		if result.Error != nil || result.RowsAffected != 1 || ctx.Err() != nil {
			return domain.ErrMCPMentorUnavailable
		}
		return nil
	})
	if err == domain.ErrMCPMentorDenied {
		return err
	}
	if err != nil || ctx.Err() != nil {
		return domain.ErrMCPMentorUnavailable
	}
	return nil
}
func (r *mcpMentorStore) ConsumeCode(ctx context.Context, hash, client, redirect, resource string, now time.Time) (*domain.MCPMentorCode, error) {
	if r == nil || r.db == nil || ctx == nil || ctx.Err() != nil || len(hash) != 64 || len(client) == 0 || len(client) > 256 || len(redirect) > 2048 || len(resource) > 2048 || now.IsZero() {
		return nil, domain.ErrMCPMentorUnavailable
	}
	var row struct {
		CodeHash, MentorID, ClientID, ConsentID, ResourceURI, RedirectURI, PKCEChallenge, Scope string
		ExpiresAt                                                                               time.Time
	}
	result := r.db.WithContext(ctx).Raw(`UPDATE public.auth_mcp_mentor_code code SET consumed_at=clock_timestamp()
		FROM public.auth_mcp_mentor_consent consent, public.auth_mcp_mentor_client client, public.auth_user account
		WHERE code.code_hash=? AND code.client_id=? AND code.redirect_uri=? AND code.resource_uri=? AND code.consumed_at IS NULL AND code.expires_at>? AND code.expires_at>clock_timestamp()
		AND consent.id=code.consent_id AND consent.mentor_id=code.mentor_id AND consent.client_id=code.client_id AND consent.resource_uri=code.resource_uri AND consent.revoked_at IS NULL AND consent.expires_at>? AND consent.expires_at>clock_timestamp()
		AND client.client_id=code.client_id AND client.resource_uri=code.resource_uri AND client.disabled_at IS NULL AND code.redirect_uri=ANY(client.redirect_uris)
		AND cardinality(consent.granted_scopes)=1 AND consent.granted_scopes<@client.allowed_scopes AND account.id=code.mentor_id AND `+mcpMentorAccountSQL+`
		RETURNING code.code_hash,code.mentor_id::text,code.client_id,code.consent_id::text,code.resource_uri,code.redirect_uri,code.pkce_challenge,consent.granted_scopes[1] AS scope,code.expires_at`, hash, client, redirect, resource, now.UTC(), now.UTC()).Scan(&row)
	if result.Error != nil || ctx.Err() != nil {
		return nil, domain.ErrMCPMentorUnavailable
	}
	if result.RowsAffected != 1 || !domain.ValidMCPMentorScope(row.Scope) {
		return nil, domain.ErrMCPMentorDenied
	}
	return &domain.MCPMentorCode{Hash: row.CodeHash, MentorID: row.MentorID, ClientID: row.ClientID, ConsentID: row.ConsentID, Resource: row.ResourceURI, RedirectURI: row.RedirectURI, Challenge: row.PKCEChallenge, Scope: row.Scope, ExpiresAt: row.ExpiresAt.UTC()}, nil
}
func (r *mcpMentorStore) Revoke(ctx context.Context, subject, client, resource string) error {
	if r == nil || r.db == nil || ctx == nil || ctx.Err() != nil || !mcpMentorBinding(subject, client, resource) {
		return domain.ErrMCPMentorUnavailable
	}
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := mcpMentorLockAccount(tx, subject); err != nil {
			return err
		}
		return tx.Exec(`UPDATE public.auth_mcp_mentor_consent SET revoked_at=clock_timestamp() WHERE mentor_id=CAST(? AS uuid) AND client_id=? AND resource_uri=? AND revoked_at IS NULL`, subject, client, resource).Error
	})
	if err != nil || ctx.Err() != nil {
		return domain.ErrMCPMentorUnavailable
	}
	return nil
}
