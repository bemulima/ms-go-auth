package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/example/auth-service/internal/domain"
	"github.com/example/auth-service/internal/infrastructure/c2bfixture"
	rpc "github.com/example/auth-service/internal/infrastructure/messaging/nats"
	repo "github.com/example/auth-service/internal/infrastructure/persistence/postgres"
	"github.com/example/auth-service/internal/usecase"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nats-io/nats.go"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
	"io"
	"os"
	"strings"
	"time"
)

func main() {
	if e := run(os.Args[1:], os.Stdin, os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, "C2-B Auth bootstrap failed:", e.Error())
		os.Exit(1)
	}
}
func run(args []string, in io.Reader, out io.Writer) error {
	return runWithDatabase(args, in, out, openDatabase)
}
func openDatabase(config *pgx.ConnConfig) (*gorm.DB, error) {
	sqlDB := stdlib.OpenDB(*config)
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent), NamingStrategy: schema.NamingStrategy{SingularTable: true}})
	if err != nil {
		_ = sqlDB.Close()
	}
	return db, err
}
func runWithDatabase(args []string, in io.Reader, out io.Writer, open func(*pgx.ConnConfig) (*gorm.DB, error)) error {
	if len(args) < 2 || (args[0] != "prepare" && args[0] != "finalize") {
		return errors.New("command denied")
	}
	i, e := domain.C2BActor(args[1])
	if e != nil {
		return e
	}
	dsn := os.Getenv("C2B_FIXTURE_DSN")
	m, config, e := c2bfixture.PrepareConnection("auth", dsn)
	if e != nil {
		return e
	}
	db, e := open(config)
	if e != nil {
		return errors.New("database unavailable")
	}
	sqlDB, e := db.DB()
	if e != nil {
		return errors.New("database unavailable")
	}
	defer sqlDB.Close()
	store := repo.C2BBootstrapRepository{DB: db}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	bootstrap := usecase.C2BBootstrap{Store: store}
	if args[0] == "prepare" {
		if len(args) != 2 {
			return errors.New("arguments denied")
		}
		key, e := c2bfixture.PrivateFile(os.Getenv("C2B_AUTH_SIGNING_KEY"))
		if e != nil || len(key) != ed25519.PrivateKeySize {
			return errors.New("dedicated signing key denied")
		}
		pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
		if base64.StdEncoding.EncodeToString(pub) != m.PublicKey {
			return errors.New("signing key mismatch")
		}
		payload, _ := json.Marshal(i)
		signed := domain.C2BSignedIntent{Schema: "c2b-signed-bootstrap.v1", Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))}
		if e = bootstrap.Prepare(ctx, i, signed); e != nil {
			return errors.New("prepare persistence denied")
		}
		return json.NewEncoder(out).Encode(signed)
	}
	if len(args) != 3 {
		return errors.New("arguments denied")
	}
	raw, e := c2bfixture.PrivateFile(args[2])
	var receipt domain.C2BReceipt
	if e != nil || c2bfixture.Strict(raw, &receipt) != nil || !receipt.Valid() || receipt.Intent != i {
		return errors.New("role receipt denied")
	}
	signed, e := store.LoadC2BIntent(ctx, i.Operation)
	if e != nil {
		return errors.New("prepared intent unavailable")
	}
	verified, e := c2bfixture.Verify(m, signed)
	if e != nil || verified != i {
		return errors.New("prepared intent proof denied")
	}
	password, e := io.ReadAll(io.LimitReader(in, 74))
	if e != nil {
		return errors.New("password input unavailable")
	}
	pw := strings.TrimSuffix(strings.TrimSuffix(string(password), "\n"), "\r")
	if strings.ContainsAny(pw, "\x00\r\n") || len(pw) < 8 || len(pw) > 72 {
		return errors.New("bounded stdin password required")
	}
	nc, e := nats.Connect(os.Getenv("NATS_URL"), nats.Timeout(3*time.Second))
	if e != nil {
		return errors.New("role authority unavailable")
	}
	defer nc.Close()
	bootstrap.Roles = rpc.NewRBACClient(nc, "rbac.assign-role", "rbac.checkRole")
	if e = bootstrap.Finalize(ctx, i, receipt, pw); e != nil {
		return errors.New("finalize binding or role readback denied")
	}
	return json.NewEncoder(out).Encode(map[string]any{"schema": "c2b-auth-bootstrap-receipt.v1", "principal_id": i.Principal, "operation_id": i.Operation, "role": i.Role, "intent_digest": i.Digest()})
}
