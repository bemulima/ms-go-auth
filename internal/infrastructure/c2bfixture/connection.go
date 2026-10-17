package c2bfixture

import (
	"errors"
	"github.com/jackc/pgx/v5"
	"net/url"
	"os"
	"strings"
)

// The retained owner proof store is the only permitted destination.
const DatabasePort = "49920"

// Gate is retained for runtime marker validation; CLI callers consume the
// parsed configuration returned by PrepareConnection instead of reparsing DSN.
func Gate(mode, dsn string) (Marker, error) {
	marker, _, err := PrepareConnection(mode, dsn)
	return marker, err
}

// PrepareConnection performs no network operation. Errors never include DSN
// or driver parse errors, which may contain credentials.
func PrepareConnection(mode, dsn string) (Marker, *pgx.ConnConfig, error) {
	marker, err := gateMarker(mode)
	if err != nil {
		return marker, nil, err
	}
	deny := errors.New("isolated PostgreSQL configuration denied")
	// Reject even explicitly empty PG* variables: no service/passfile, options,
	// TLS, resolver or future driver environment defaults are fixture authority.
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "PG") {
			return marker, nil, deny
		}
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme != "postgres" || u.Opaque != "" || u.User == nil || u.Host != "127.0.0.1:"+DatabasePort || u.Fragment != "" || strings.Contains(dsn, "#") || u.RawPath != "" || u.RawQuery != "sslmode=disable" {
		return marker, nil, deny
	}
	db, user := "c2b_auth_20261016", "c2b_auth_fixture"
	switch mode {
	case "rbac":
		db, user = "c2b_rbac_20261016", "c2b_rbac_fixture"
	case "auth-runtime":
		user = "c2b_auth_runtime"
	case "auth":
	default:
		return marker, nil, deny
	}
	// Require literal identity/path. Password percent escaping remains necessary
	// for legitimate opaque secrets; encoded connection parameter names are denied.
	if u.Path != "/"+db || u.EscapedPath() != "/"+db || u.User.Username() != user || !strings.HasPrefix(dsn, "postgres://"+user+":") {
		return marker, nil, deny
	}
	if password, ok := u.User.Password(); !ok || password == "" {
		return marker, nil, deny
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return marker, nil, deny
	}
	effective := config
	if effective.Host != "127.0.0.1" || effective.Port != 49920 || effective.User != user || effective.Database != db || effective.TLSConfig != nil || len(effective.RuntimeParams) != 0 {
		return marker, nil, deny
	}
	// sslmode=disable at one literal host must not create any fallback at all.
	for _, fallback := range effective.Fallbacks {
		if fallback == nil || fallback.Host != "127.0.0.1" || fallback.Port != 49920 || fallback.TLSConfig != nil {
			return marker, nil, deny
		}
	}
	if len(effective.Fallbacks) != 0 {
		return marker, nil, deny
	}
	return marker, config, nil
}
