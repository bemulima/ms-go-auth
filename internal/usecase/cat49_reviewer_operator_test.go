package usecase

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/example/auth-service/internal/domain"
)

type cat49OperatorStoreFake struct {
	record domain.CAT49RegistrationReceipt
	writes int
	activated bool
}
func (s *cat49OperatorStoreFake) RegisterCAT49Reviewer(_ context.Context,r domain.CAT49ReviewerRegistration) (bool,error) {
	s.record=r.Receipt;s.writes++;return true,nil
}
func (s *cat49OperatorStoreFake) ReadCAT49Registration(_ context.Context,id string) (domain.CAT49RegistrationReceipt,error) {
	if s.record.PrincipalID!=id {return domain.CAT49RegistrationReceipt{},errors.New("not registered")}
	return s.record,nil
}
func (s *cat49OperatorStoreFake) ActivateCAT49Reviewer(context.Context,domain.CAT49ReviewerActivation) (bool,error) {
	s.activated=true;return true,nil
}
func TestCAT49ReviewerRegistrationIsSignedAndTightlyScoped(t *testing.T) {
	s:=&cat49OperatorStoreFake{}
	input:=CAT49RegistrationCommand{RunID:"cat49b1717",
		RequestID:"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		PrincipalID:"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		AuthDatabase:"cat49_auth_business",Operator:"cat49-owner",
		Password:"private-reviewer-test-password"}
	key:=[]byte(strings.Repeat("k",48))
	proof,err:=CAT49RegisterReviewer(context.Background(),s,input,key)
	if err!=nil || s.writes!=1 || proof.ReceiptDigest=="" || proof.Signature=="" {
		t.Fatalf("valid registration denied: %v",err)
	}
	for _,alter:=range []func(*CAT49RegistrationCommand){
		func(p *CAT49RegistrationCommand){p.AuthDatabase="lw_auth"},
		func(p *CAT49RegistrationCommand){p.RunID="otherproject"},
		func(p *CAT49RegistrationCommand){p.PrincipalID="invalid"},
		func(p *CAT49RegistrationCommand){p.Password="short"},
	} {
		bad:=input;alter(&bad)
		if _,e:=CAT49RegisterReviewer(context.Background(),s,bad,key);e==nil {
			t.Fatal("foreign/unbounded registration accepted")
		}
	}
}
