package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/example/auth-service/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

const (
	fixtureRunID    = "abc12345"
	fixtureUserID   = "53b0d885-86e5-5c9c-a123-693f9d1ac301"
	fixturePassword = "verification-only-password"
)

type fixtureUserStore struct {
	users   map[string]*domain.AuthUser
	creates int
}

func (s *fixtureUserStore) CreateVerificationIfAbsent(_ context.Context, candidate *domain.AuthUser) (*domain.AuthUser, bool, error) {
	if s.users == nil {
		s.users = map[string]*domain.AuthUser{}
	}
	if existing := s.users[candidate.Email]; existing != nil {
		return existing, false, nil
	}
	s.creates++
	s.users[candidate.Email] = candidate
	return candidate, true, nil
}

type fixtureRoleClient struct {
	assigned  map[string]string
	assignErr error
	checkErr  error
	assigns   int
}

func (c *fixtureRoleClient) AssignRole(_ context.Context, userID, role string) error {
	c.assigns++
	if c.assignErr != nil {
		return c.assignErr
	}
	if c.assigned == nil {
		c.assigned = map[string]string{}
	}
	c.assigned[userID] = role
	return nil
}

func (c *fixtureRoleClient) CheckRole(_ context.Context, userID, role string) (bool, error) {
	if c.checkErr != nil {
		return false, c.checkErr
	}
	return c.assigned[userID] == role, nil
}

func fixtureInput() VerificationFixtureInput {
	return VerificationFixtureInput{RunID: fixtureRunID, UserID: fixtureUserID, Password: fixturePassword}
}

func TestVerificationFixtureCreatesAuthCredentialAndStudentRole(t *testing.T) {
	store := &fixtureUserStore{}
	roles := &fixtureRoleClient{}
	fixture := NewVerificationFixture(store, roles)

	result, err := fixture.Provision(context.Background(), fixtureInput())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "created" || result.RunID != fixtureRunID || result.IdentityID != fixtureUserID || result.Role != "student" {
		t.Fatalf("unexpected fixture result: %+v", result)
	}
	user := store.users["v1+"+fixtureRunID+"@verification.invalid"]
	if user == nil || user.PasswordHash == nil || roles.assigned[fixtureUserID] != "student" {
		t.Fatal("Auth credential or canonical STUDENT assignment is missing")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(fixturePassword)); err != nil {
		t.Fatal("stored Auth-owned password hash does not verify")
	}
	if roles.assigns != 1 || store.creates != 1 {
		t.Fatalf("expected one Auth creation and one RBAC assignment; creates=%d assigns=%d", store.creates, roles.assigns)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), fixturePassword) || strings.Contains(string(encoded), *user.PasswordHash) || strings.Contains(string(encoded), "@verification.invalid") {
		t.Fatal("fixture output contains password, hash, or email")
	}
}

func TestVerificationFixtureExactReplayIsSafeAndDoesNotResetPassword(t *testing.T) {
	store := &fixtureUserStore{}
	roles := &fixtureRoleClient{}
	fixture := NewVerificationFixture(store, roles)

	first, err := fixture.Provision(context.Background(), fixtureInput())
	if err != nil {
		t.Fatal(err)
	}
	storedHash := *store.users["v1+"+fixtureRunID+"@verification.invalid"].PasswordHash
	second, err := fixture.Provision(context.Background(), fixtureInput())
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "created" || second.Status != "already_present" || first.IdentityID != second.IdentityID {
		t.Fatalf("unexpected replay results: first=%+v second=%+v", first, second)
	}
	if store.creates != 1 || roles.assigns != 1 || *store.users["v1+"+fixtureRunID+"@verification.invalid"].PasswordHash != storedHash {
		t.Fatal("exact replay mutated the credential or repeated an owner write")
	}
}

func TestVerificationFixtureConflictsDoNotMutateExistingIdentity(t *testing.T) {
	store := &fixtureUserStore{}
	roles := &fixtureRoleClient{}
	fixture := NewVerificationFixture(store, roles)
	if _, err := fixture.Provision(context.Background(), fixtureInput()); err != nil {
		t.Fatal(err)
	}
	stored := store.users["v1+"+fixtureRunID+"@verification.invalid"]
	storedHash := *stored.PasswordHash

	wrongPassword := fixtureInput()
	wrongPassword.Password = "different-password"
	if _, err := fixture.Provision(context.Background(), wrongPassword); err == nil {
		t.Fatal("expected password conflict")
	}

	wrongID := fixtureInput()
	wrongID.UserID = "9f804a7a-28d8-5cb7-bd88-4bf11d5a7e87"
	if _, err := fixture.Provision(context.Background(), wrongID); err == nil {
		t.Fatal("expected identity conflict")
	}
	if store.creates != 1 || roles.assigns != 1 || *stored.PasswordHash != storedHash {
		t.Fatal("conflicting replay changed Auth or RBAC state")
	}
}

func TestVerificationFixtureRBACFailureIsIncompleteAndNeverSuccessful(t *testing.T) {
	store := &fixtureUserStore{}
	roles := &fixtureRoleClient{assignErr: errors.New("sensitive lower-layer failure")}
	fixture := NewVerificationFixture(store, roles)

	result, err := fixture.Provision(context.Background(), fixtureInput())
	var fixtureErr *VerificationFixtureError
	if result != nil || !errors.As(err, &fixtureErr) || fixtureErr.Status != "incomplete" || fixtureErr.Stage != "rbac_assignment" {
		t.Fatalf("expected explicit incomplete assignment result, result=%+v err=%v", result, err)
	}
	if strings.Contains(err.Error(), fixturePassword) || strings.Contains(err.Error(), "sensitive lower-layer failure") {
		t.Fatal("fixture error exposed sensitive or lower-layer details")
	}
	if store.creates != 1 || roles.assigned[fixtureUserID] != "" {
		t.Fatal("expected Auth row to remain incomplete in the disposable DB without a successful RBAC role")
	}
}

func TestVerificationFixtureRejectsInvalidRunAndPassword(t *testing.T) {
	fixture := NewVerificationFixture(&fixtureUserStore{}, &fixtureRoleClient{})
	input := fixtureInput()
	input.RunID = "../shared"
	if _, err := fixture.Provision(context.Background(), input); err == nil {
		t.Fatal("expected invalid run ID rejection")
	}
	input = fixtureInput()
	input.Password = strings.Repeat("p", 73)
	if _, err := fixture.Provision(context.Background(), input); err == nil {
		t.Fatal("expected bcrypt length rejection")
	}
}
