package main

import (
	"crypto/rsa"
	"errors"
	"reflect"

	natsadapter "github.com/example/auth-service/internal/infrastructure/messaging/nats"
	repo "github.com/example/auth-service/internal/infrastructure/persistence/postgres"
	"github.com/example/auth-service/internal/tokenverify"
	internalhttp "github.com/example/auth-service/internal/transport/http/private"
	"github.com/example/auth-service/internal/usecase"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

var ErrMentorCompositionUnavailable = errors.New("mentor composition unavailable")

// MentorCompositionKeyPair is already-provided key material, not a file path,
// environment variable name or instruction to provision a credential.
type MentorCompositionKeyPair struct {
	PrivatePEM string
	PublicPEM  string
}

// MentorCompositionConfig remains a pure constructor input. Its zero value is
// disabled; the explicit runtime opt-in maps validated configuration into it.
type MentorCompositionConfig struct {
	Enabled              bool
	RoleDecision         MentorCompositionKeyPair
	OwnerLookup          MentorCompositionKeyPair
	RBACReplyPublicPEM   string
	MentorReplyPublicPEM string
}

// MentorCompositionDependencies are existing Auth-owned dependencies. The
// caller supplies the actual configured access-token parser, DB and requester;
// composition neither opens nor closes them and does not probe their health.
type MentorCompositionDependencies struct {
	DB        *gorm.DB
	Parser    tokenverify.Parser
	Requester natsadapter.MentorOwnerNATSRequester
}

// NewMentorComposition constructs the concrete, unmounted authority boundary.
// It does not call App.New/Run, read configuration, query SQL, request an owner,
// mount a route or open a listener. Disabled returns no handler before even
// inspecting the supplied dependencies or keys.
func NewMentorComposition(cfg MentorCompositionConfig, deps MentorCompositionDependencies) (*internalhttp.MentorHTTPAuthorityHandler, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if mentorCompositionMissing(deps.Parser) || mentorCompositionMissing(deps.Requester) ||
		deps.DB == nil || deps.DB.Config == nil || deps.DB.Statement == nil || deps.DB.Error != nil ||
		mentorCompositionMissing(deps.DB.ConnPool) || mentorCompositionMissing(deps.DB.Statement.ConnPool) ||
		!mentorCompositionDistinctKeys(cfg) {
		return nil, ErrMentorCompositionUnavailable
	}
	reader, err := repo.NewMentorSessionReader(deps.DB)
	if err != nil {
		return nil, ErrMentorCompositionUnavailable
	}
	sessions, err := usecase.NewMentorLiveSessionVerifier(deps.Parser, reader)
	if err != nil {
		return nil, ErrMentorCompositionUnavailable
	}
	owners, err := natsadapter.NewMentorOwnerConfirmationClient(deps.Requester,
		cfg.OwnerLookup.PrivatePEM, cfg.OwnerLookup.PublicPEM,
		cfg.RBACReplyPublicPEM, cfg.MentorReplyPublicPEM)
	if err != nil {
		return nil, ErrMentorCompositionUnavailable
	}
	authority, err := usecase.NewMentorHTTPAuthority(cfg.RoleDecision.PrivatePEM,
		cfg.RoleDecision.PublicPEM, sessions, owners, owners)
	if err != nil {
		return nil, ErrMentorCompositionUnavailable
	}
	handler, err := internalhttp.NewMentorHTTPAuthorityHandler(authority)
	if err != nil {
		return nil, ErrMentorCompositionUnavailable
	}
	return handler, nil
}

func mentorCompositionDistinctKeys(cfg MentorCompositionConfig) bool {
	encoded := [...]string{cfg.RoleDecision.PublicPEM, cfg.OwnerLookup.PublicPEM, cfg.RBACReplyPublicPEM, cfg.MentorReplyPublicPEM}
	keys := make([]*rsa.PublicKey, 0, len(encoded))
	for _, material := range encoded {
		key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(material))
		if err != nil || key == nil || key.N == nil || key.N.Sign() <= 0 || key.N.BitLen() < 2048 || key.E < 3 || key.E%2 == 0 {
			return false
		}
		for _, prior := range keys {
			// A differently encoded PEM or exponent is not a different RSA key
			// domain when the modulus is shared. Private/public pair matching is
			// additionally enforced by the actual owner/issuer constructors.
			if prior.N.Cmp(key.N) == 0 {
				return false
			}
		}
		keys = append(keys, key)
	}
	return true
}

func mentorCompositionMissing(dependency any) bool {
	if dependency == nil {
		return true
	}
	value := reflect.ValueOf(dependency)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
