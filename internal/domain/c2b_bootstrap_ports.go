package domain

import "context"

type C2BBootstrapStore interface {
	SaveC2BIntent(context.Context, C2BIntent, C2BSignedIntent) error
	LoadC2BIntent(context.Context, string) (C2BSignedIntent, error)
	FinalizeC2B(context.Context, C2BIntent, C2BReceipt, *AuthUser) (*AuthUser, error)
}
type C2BMentorAuditReader interface {
	C2BMentorEligible(context.Context, string) (bool, error)
}
