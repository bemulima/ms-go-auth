// CAT-49 one-shot Auth reviewer operator. Not mounted in Auth server or HTTP.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	natsadapter "github.com/example/auth-service/internal/infrastructure/messaging/nats"
	repo "github.com/example/auth-service/internal/infrastructure/persistence/postgres"
	"github.com/example/auth-service/internal/usecase"
	"github.com/jackc/pgx/v5/pgxpool"
	nats "github.com/nats-io/nats.go"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const markerPath = "/run/cat49/ownership.json"

type ownership struct {
	Schema       string `json:"schema"`
	Purpose      string `json:"purpose"`
	RunID        string `json:"run_id"`
	Project      string `json:"project"`
	Network      string `json:"network"`
	AuthDatabase string `json:"auth_database"`
	RBACDatabase string `json:"rbac_database"`
	AuthUser     string `json:"auth_user"`
	PostgresHost string `json:"postgres_host"`
	PostgresPort uint16 `json:"postgres_port"`
	NATSURL      string `json:"nats_url"`
}

func (m ownership) valid() bool {
	run := regexp.MustCompile("^cat49[a-z0-9]{5,20}$")
	db := regexp.MustCompile("^cat49_[a-z0-9_]{4,60}$")
	user := regexp.MustCompile("^[a-z][a-z0-9_]{1,60}$")
	return m.Schema == "cat49-disposable-ownership.v1" &&
		m.Purpose == "cat49-reviewer" && run.MatchString(m.RunID) &&
		m.Project == "lp-v1-"+m.RunID && m.Network == m.Project+"-net" &&
		db.MatchString(m.AuthDatabase) && db.MatchString(m.RBACDatabase) &&
		m.AuthDatabase != m.RBACDatabase && user.MatchString(m.AuthUser) &&
		(m.PostgresHost == "127.0.0.1" || m.PostgresHost == "localhost") &&
		m.PostgresPort > 0 && regexp.MustCompile("^nats://127\\.0\\.0\\.1:[1-9][0-9]{0,4}$").MatchString(m.NATSURL)
}
func privateFile(path string, max int) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("CAT49 private path denied")
	}
	stat, err := os.Lstat(path)
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0 ||
		stat.Size() <= 0 || stat.Size() > int64(max) {
		return nil, errors.New("CAT49 private file denied")
	}
	value, err := os.ReadFile(path)
	if err != nil || len(value) == 0 || len(value) > max {
		return nil, errors.New("CAT49 private file denied")
	}
	return value, nil
}
func marker() (ownership, error) {
	var m ownership
	raw, err := privateFile(markerPath, 4096)
	if err != nil {
		return m, err
	}
	if json.Unmarshal(raw, &m) != nil || !m.valid() {
		return m, errors.New("CAT49 ownership marker rejected")
	}
	return m, nil
}
func execute() error {
	if os.Getenv("APP_ENV") != "cat49-disposable-operator" ||
		os.Getenv("AUTH_CAT49_REVIEWER_OPERATOR") != "enabled" ||
		os.Getenv("AUTH_JWT_SECRET") != "" ||
		os.Getenv("AUTH_JWT_PRIVATE_KEY") != "" ||
		os.Getenv("AUTH_JWT_PUBLIC_KEY") != "" {
		return errors.New("CAT49 operator disabled")
	}
	flags := flag.NewFlagSet("ms-go-auth-cat49-reviewer", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	action := flags.String("action", "", "register or activate")
	runID := flags.String("run-id", "", "exact owned run")
	requestID := flags.String("request-id", "", "one-shot operation")
	principalID := flags.String("principal-id", "", "new reviewer principal")
	operator := flags.String("operator", "", "local operator audit name")
	if flags.Parse(os.Args[1:]) != nil || flags.NArg() != 0 ||
		(*action != "register" && *action != "activate") {
		return errors.New("CAT49 operator arguments denied")
	}
	owner, err := marker()
	if err != nil || *runID != owner.RunID {
		return errors.New("CAT49 operator ownership denied")
	}
	authKey, err := privateFile(os.Getenv("AUTH_CAT49_REGISTRATION_KEY_FILE"), 4096)
	if err != nil {
		return err
	}
	rbacKey, err := privateFile(os.Getenv("AUTH_CAT49_RBAC_GRANT_KEY_FILE"), 4096)
	if err != nil || string(authKey) == string(rbacKey) {
		return errors.New("CAT49 distinct keys required")
	}
	dsn := os.Getenv("AUTH_CAT49_REVIEWER_DSN")
	if dsn == "" {
		return errors.New("CAT49 Auth DSN missing")
	}
	pgcfg, parseErr := pgxpool.ParseConfig(dsn)
	if parseErr != nil || pgcfg.ConnConfig.Database != owner.AuthDatabase ||
		pgcfg.ConnConfig.User != owner.AuthUser || pgcfg.ConnConfig.Host != owner.PostgresHost ||
		pgcfg.ConnConfig.Port != owner.PostgresPort || len(pgcfg.ConnConfig.Fallbacks) != 0 {
		return errors.New("CAT49 Auth DSN identity denied")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return errors.New("CAT49 Auth database unavailable")
	}
	sqldb, err := db.DB()
	if err != nil {
		return errors.New("CAT49 Auth database unavailable")
	}
	defer sqldb.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var actual struct {
		Database string
		Actor    string
		Super    bool
	}
	if db.WithContext(ctx).Raw("SELECT current_database() AS database,current_user AS actor,(SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AS super").Scan(&actual).Error != nil ||
		actual.Database != owner.AuthDatabase || actual.Actor != owner.AuthUser || actual.Super {
		return errors.New("CAT49 Auth DB identity denied")
	}
	// Explicitly prove the connection is owned by the task, not a shared DB.
	var server struct {
		Host string
		Port int
	}
	if db.WithContext(ctx).Raw("SELECT inet_server_addr()::text AS host, inet_server_port() AS port").Scan(&server).Error != nil ||
		server.Port != int(owner.PostgresPort) {
		return errors.New("CAT49 Auth DB listener denied")
	}
	if strings.Contains(dsn, "lw_auth") || strings.Contains(dsn, "learning-workspace") {
		return errors.New("CAT49 shared Auth DSN denied")
	}
	store := repo.NewCAT49ReviewerOperatorRepository(db)
	if *action == "register" {
		raw, e := io.ReadAll(io.LimitReader(os.Stdin, 513))
		if e != nil || len(raw) > 512 {
			return errors.New("CAT49 input denied")
		}
		password := strings.TrimSuffix(string(raw), "\n")
		password = strings.TrimSuffix(password, "\r")
		result, e := usecase.CAT49RegisterReviewer(ctx, store, usecase.CAT49RegistrationCommand{
			RunID: *runID, RequestID: *requestID, PrincipalID: *principalID,
			AuthDatabase: owner.AuthDatabase, Operator: *operator, Password: password,
		}, authKey)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if e != nil || len(raw) > 4096 {
		return errors.New("CAT49 RBAC proof denied")
	}
	if !regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$").MatchString(*principalID) ||
		!regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$").MatchString(*requestID) {
		return errors.New("CAT49 activation IDs denied")
	}
	var signed struct {
		RequestID   string `json:"request_id"`
		RunID       string `json:"run_id"`
		PrincipalID string `json:"principal_id"`
	}
	if json.Unmarshal(raw, &signed) != nil || signed.RequestID != *requestID ||
		signed.RunID != *runID || signed.PrincipalID != *principalID {
		return errors.New("CAT49 activation proof identity denied")
	}
	nc, e := nats.Connect(owner.NATSURL, nats.Timeout(3*time.Second))
	if e != nil {
		return errors.New("CAT49 RBAC readback unavailable")
	}
	defer nc.Close()
	roles := natsadapter.NewRBACClient(nc, "rbac.assign-role", "rbac.checkRole")
	if e = usecase.CAT49ActivateReviewer(ctx, store, roles, *principalID, raw, rbacKey); e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{
		"status": "activated", "run_id": *runID, "principal_id": *principalID,
	})
}
func main() {
	if err := execute(); err != nil {
		fmt.Fprintln(os.Stderr, "CAT49 Auth reviewer operator denied")
		os.Exit(1)
	}
}
