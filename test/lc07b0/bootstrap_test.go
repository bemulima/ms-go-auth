package lc07b0_test

import (
	"context"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/example/auth-service/internal/domain"
	adapter "github.com/example/auth-service/internal/infrastructure/messaging/nats"
	nats "github.com/nats-io/nats.go"
	"golang.org/x/crypto/bcrypt"
)

func TestProvisionDisposableIdentity(t *testing.T) {
	dir, m, c, digest := load(t)
	u, e := url.Parse(c.NATSURL)
	if e != nil || u.Scheme != "nats" || u.Host != "127.0.0.1:"+strconv.Itoa(m.NATSPort) || u.User == nil || u.User.Username() != "bootstrap" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		t.Fatal("isolated owner broker required")
	}
	conn := openOwned(t, m, c, digest)
	defer conn.Close(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tx, e := conn.Begin(ctx)
	if e != nil {
		t.Fatal("owner transaction unavailable")
	}
	defer tx.Rollback(ctx)
	fail := func() { t.Fatal("immutable fixture credential conflict") }
	type principal struct {
		actor, id, email string
		password         []byte
		existing         bool
	}
	records := []principal{}
	// Validate EVERY existing Auth binding before the first cross-owner write.
	for _, actor := range []string{"admin", "student", "teacher"} {
		id, email := identity(m.Run, actor)
		pw, e := privateRead(filepath.Join(dir, actor+".password"))
		if e != nil || len(pw) < 20 || len(pw) > 72 || strings.ContainsAny(string(pw), "\r\n\x00") {
			t.Fatal("bounded private credential required")
		}
		if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, digest+actor); e != nil {
			fail()
		}
		var count int
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM auth_user WHERE id=$1 OR email=$2`, id, email).Scan(&count); e != nil || count > 1 {
			fail()
		}
		if count == 1 {
			var actualID, actualEmail, hash, proof, identityEmail, identityRun string
			var verified bool
			e = tx.QueryRow(ctx, `SELECT u.id::text,u.email,u.password_hash,u.email_verified,coalesce(i.raw_profile->>'lc07_b0_owner',''),i.email,coalesce(i.raw_profile->>'run','') FROM auth_user u JOIN auth_identity i ON i.user_id=u.id AND i.provider='email' AND i.provider_user_id=$2 WHERE u.id=$1`, id, email).Scan(&actualID, &actualEmail, &hash, &verified, &proof, &identityEmail, &identityRun)
			if e != nil || actualID != id || actualEmail != email || !verified || proof != digest || identityEmail != email || identityRun != m.Run || bcrypt.CompareHashAndPassword([]byte(hash), pw) != nil {
				fail()
			}
		}
		records = append(records, principal{actor, id, email, pw, count == 1})
	}
	nc, e := nats.Connect(c.NATSURL, nats.Timeout(3*time.Second))
	if e != nil {
		t.Fatal("owner broker unavailable")
	}
	defer nc.Close()
	users := adapter.NewUserClient(nc, "user.create-user")
	roles := adapter.NewRBACClient(nc, "rbac.assign-role", "rbac.checkRole")
	for _, p := range records {
		ok, e := roles.CheckRole(ctx, p.id, p.actor)
		if e != nil || !ok {
			t.Fatal("authoritative role readback required")
		}
	}
	// Coordinator's exact User store pre/post readback is mandatory; RPC ack alone is insufficient.
	for _, p := range records {
		if e = users.CreateUser(ctx, domain.UserProvisionRequest{ID: p.id, Email: p.email, Source: "auth", Type: "email"}); e != nil {
			t.Fatal("User owner projection unavailable")
		}
	}
	for _, p := range records {
		if p.existing {
			continue
		}
		hash, e := bcrypt.GenerateFromPassword(p.password, bcrypt.DefaultCost)
		if e != nil {
			fail()
		}
		if _, e = tx.Exec(ctx, `INSERT INTO auth_user(id,email,password_hash,email_verified) VALUES($1,$2,$3,true)`, p.id, p.email, string(hash)); e != nil {
			fail()
		}
		profile, _ := json.Marshal(map[string]string{"lc07_b0_owner": digest, "run": m.Run})
		if _, e = tx.Exec(ctx, `INSERT INTO auth_identity(user_id,provider,provider_user_id,email,raw_profile) VALUES($1,'email',$2,$2,$3)`, p.id, p.email, profile); e != nil {
			fail()
		}
	}
	if e = tx.Commit(ctx); e != nil {
		fail()
	}
	receipt(t, dir, "auth", digest, m)
}
