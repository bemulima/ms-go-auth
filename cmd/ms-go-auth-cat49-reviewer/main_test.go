package main

import "testing"

func TestCAT49AuthReviewerMarkerAndDisabledGuard(t *testing.T) {
	good:=ownership{
		Schema:"cat49-disposable-ownership.v1",Purpose:"cat49-reviewer",
		RunID:"cat49b1717",Project:"lp-v1-cat49b1717",
		Network:"lp-v1-cat49b1717-net",AuthDatabase:"cat49_auth_business",
		RBACDatabase:"cat49_rbac_business",AuthUser:"cat49_auth",
		PostgresHost:"127.0.0.1",PostgresPort:5432,NATSURL:"nats://127.0.0.1:4222",
	}
	if !good.valid(){t.Fatal("valid task marker denied")}
	for _,bad:=range []func(*ownership){
		func(v *ownership){v.AuthDatabase="lw_auth"},
		func(v *ownership){v.RunID="foreign"},
		func(v *ownership){v.Network="shared"},
		func(v *ownership){v.Purpose="v1-a-auth-fixture"},
		func(v *ownership){v.NATSURL="nats://shared:4222"},
	} {
		m:=good;bad(&m);if m.valid(){t.Fatal("unsafe marker accepted")}
	}
}
