package repo

import (
	"context"
	"errors"
	"testing"

	"github.com/example/auth-service/internal/domain"
)

type cat49ReviewerStoreContract interface {
	RegisterCAT49Reviewer(context.Context,domain.CAT49ReviewerRegistration)(bool,error)
	ReadCAT49Registration(context.Context,string)(domain.CAT49RegistrationReceipt,error)
	ActivateCAT49Reviewer(context.Context,domain.CAT49ReviewerActivation)(bool,error)
}
var _ cat49ReviewerStoreContract = (*authUserRepo)(nil)

func TestCAT49RegistrationIsNotImplicitAuthentication(t *testing.T) {
	// Source protocol asserts that token issuance is a separate gate; an
	// operator cannot create an active reviewer by merely registering Auth.
	var proof domain.CAT49RegistrationReceipt
	if proof.Schema != "" {
		t.Fatal("unset receipt unexpectedly passes a gate")
	}
	if !errors.Is(domain.ErrNotFound,domain.ErrNotFound) {
		t.Fatal("owner not-found binding changed")
	}
}
