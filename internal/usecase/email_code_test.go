package usecase

import (
	"context"
	"github.com/example/auth-service/internal/domain"
	"github.com/vmihailenco/msgpack/v5"
	"regexp"
	"testing"
)

type codePolicyUsers struct{}

func (codePolicyUsers) FindByEmail(context.Context, string) (*domain.AuthUser, error) {
	return nil, domain.ErrNotFound
}
func (codePolicyUsers) FindByID(context.Context, string) (*domain.AuthUser, error) {
	panic("unexpected read")
}
func (codePolicyUsers) Create(context.Context, *domain.AuthUser) error {
	panic("unexpected account creation")
}
func (codePolicyUsers) Update(context.Context, *domain.AuthUser) error {
	panic("unexpected account update")
}

type codePolicyStore struct {
	calls          int
	alwaysConflict bool
}

func (s *codePolicyStore) Execute(_ context.Context, action string, args []interface{}) ([]interface{}, error) {
	if action != "code_start" {
		panic("unexpected storage action")
	}
	s.calls++
	if s.alwaysConflict || s.calls == 1 {
		return []interface{}{"code_conflict"}, nil
	}
	return []interface{}{"ok", []interface{}{}}, nil
}

type codePolicyMail struct {
	calls int
	valid bool
}

func (m *codePolicyMail) Send(_ context.Context, _ string, _ string, body string) error {
	m.calls++
	m.valid = regexp.MustCompile(`verification code: [0-9]{6}\.`).MatchString(body)
	return nil
}
func TestEmailCodeAllocationRetriesWithoutDeliveringConflictingCode(t *testing.T) {
	store, mail := &codePolicyStore{}, &codePolicyMail{}
	s := &authService{users: codePolicyUsers{}, codes: &EmailCodes{store: store, mail: mail, key: []byte("test-only-email-code-key-32-bytes!"), originLimit: 20}}
	if err := s.StartEmailCode(context.Background(), "registration", "allocation@example.test", "127.0.0.1"); err != nil {
		t.Fatal("fresh code should be allocated")
	}
	if store.calls != 2 || mail.calls != 1 || !mail.valid {
		t.Fatal("collision must retry before sending one six-digit code")
	}
}
func TestEmailCodeAllocationFailsClosedAfterBoundedCollisions(t *testing.T) {
	store, mail := &codePolicyStore{alwaysConflict: true}, &codePolicyMail{}
	s := &authService{users: codePolicyUsers{}, codes: &EmailCodes{store: store, mail: mail, key: []byte("test-only-email-code-key-32-bytes!"), originLimit: 20}}
	if s.StartEmailCode(context.Background(), "registration", "allocation@example.test", "127.0.0.1") == nil {
		t.Fatal("allocation must fail closed")
	}
	if store.calls != 10 || mail.calls != 0 {
		t.Fatal("bounded collisions must never send a code")
	}
}

func TestRegistrationGrantExpiryFromMessagePack(t *testing.T) {
	// Current Unix timestamps use MessagePack uint32, as returned by Tarantool.
	raw, err := msgpack.Marshal(uint32(1809447000))
	if err != nil {
		t.Fatal(err)
	}
	var decoded interface{}
	if err = msgpack.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	expiry, ok := codeNumber(decoded)
	if !ok || expiry != 1809447000 {
		t.Fatalf("registration grant expiry rejected MessagePack type %T", decoded)
	}
}
