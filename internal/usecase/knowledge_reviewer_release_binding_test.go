package usecase

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

// All keys and build/config pins here are synthetic, generated only in memory.
// They are never accepted deployment bindings or persisted artifacts.
func syntheticReviewerRelease(t *testing.T, key *rsa.PublicKey, publicPEM []byte) KnowledgeReviewerReleaseBindingV1 {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	file := sha256.Sum256(publicPEM)
	spki := sha256.Sum256(der)
	r := KnowledgeReviewerReleaseBindingV1{Schema: KnowledgeReviewerReleaseBindingSchemaV1, Issuer: "synthetic-auth.test", PublicKeyOwner: "ms-go-auth", PEMSHA256: hex.EncodeToString(file[:]), SPKISHA256: hex.EncodeToString(spki[:]), Algorithm: "RS256"}
	r.Auth = KnowledgeReviewerReleaseSourceV1{SourceCommit: strings.Repeat("a", 40), ConfigReceiptSHA256: strings.Repeat("b", 64), PublicSPKISHA256: r.SPKISHA256, Issuer: r.Issuer}
	r.Planner = KnowledgeReviewerReleaseSourceV1{SourceCommit: strings.Repeat("c", 40), ConfigReceiptSHA256: strings.Repeat("d", 64), PublicSPKISHA256: r.SPKISHA256, Issuer: r.Issuer}
	return r
}

func TestKnowledgeReviewerReleaseBindingCanonicalPublicFingerprint(t *testing.T) {
	key, _, pkcs1 := reviewerKeyPEMs(t)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pkix := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	var previous KnowledgeReviewerReleaseBindingEvidenceV1
	for _, input := range [][]byte{[]byte(pkcs1), pkix, append(append([]byte{}, pkix...), '\n')} {
		r := syntheticReviewerRelease(t, &key.PublicKey, input)
		e, err := ValidateKnowledgeReviewerReleaseBinding(r, input)
		if err != nil {
			t.Fatal(err)
		}
		if e.Status != KnowledgeReviewerReleaseSourceOnly || e.RSABits != 2048 || e.Issuer != r.Issuer {
			t.Fatal("source-only invariant")
		}
		if previous.SPKISHA256 != "" && (previous.SPKISHA256 != e.SPKISHA256 || previous.PEMSHA256 == e.PEMSHA256) {
			t.Fatal("SPKI normalization or exact file hash lost")
		}
		previous = e
	}
}

func TestKnowledgeReviewerReleaseBindingIssuerPlannerCompatibilityBoundary(t *testing.T) {
	key, _, publicPEM := reviewerKeyPEMs(t)
	input := []byte(publicPEM)
	for _, size := range []int{255, 256} {
		r := syntheticReviewerRelease(t, &key.PublicKey, input)
		r.Issuer = strings.Repeat("a", size)
		r.Auth.Issuer = r.Issuer
		r.Planner.Issuer = r.Issuer
		e, err := ValidateKnowledgeReviewerReleaseBinding(r, input)
		if size == 255 {
			if err != nil || e.Status != KnowledgeReviewerReleaseSourceOnly {
				t.Fatal("shared255byteissuerrejected", err)
			}
		} else if !errors.Is(err, ErrKnowledgeReviewerReleaseBinding) {
			t.Fatal("Planner-incompatible256byteissueraccepted")
		}
	}
}

func TestKnowledgeReviewerReleaseBindingRejectsMetadataAndArtifactMismatch(t *testing.T) {
	key, _, raw := reviewerKeyPEMs(t)
	input := []byte(raw)
	base := syntheticReviewerRelease(t, &key.PublicKey, input)
	for _, tc := range []struct {
		name   string
		change func(*KnowledgeReviewerReleaseBindingV1)
	}{
		{"schema", func(r *KnowledgeReviewerReleaseBindingV1) { r.Schema = "other" }},
		{"no issuer", func(r *KnowledgeReviewerReleaseBindingV1) { r.Issuer = "" }},
		{"issuer alias", func(r *KnowledgeReviewerReleaseBindingV1) { r.Issuer = " synthetic-auth.test" }},
		{"issuer control", func(r *KnowledgeReviewerReleaseBindingV1) { r.Issuer = "auth\nissuer" }},
		{"auth issuer", func(r *KnowledgeReviewerReleaseBindingV1) { r.Auth.Issuer = "other" }},
		{"planner issuer", func(r *KnowledgeReviewerReleaseBindingV1) { r.Planner.Issuer = "other" }},
		{"owner", func(r *KnowledgeReviewerReleaseBindingV1) { r.PublicKeyOwner = "caller" }},
		{"algorithm", func(r *KnowledgeReviewerReleaseBindingV1) { r.Algorithm = "HS256" }},
		{"file hash", func(r *KnowledgeReviewerReleaseBindingV1) { r.PEMSHA256 = strings.Repeat("a", 64) }},
		{"SPKI hash", func(r *KnowledgeReviewerReleaseBindingV1) { r.SPKISHA256 = strings.Repeat("a", 64) }},
		{"auth key", func(r *KnowledgeReviewerReleaseBindingV1) { r.Auth.PublicSPKISHA256 = strings.Repeat("a", 64) }},
		{"planner key", func(r *KnowledgeReviewerReleaseBindingV1) { r.Planner.PublicSPKISHA256 = strings.Repeat("a", 64) }},
		{"missing build", func(r *KnowledgeReviewerReleaseBindingV1) { r.Auth.SourceCommit = "" }},
		{"invalid build", func(r *KnowledgeReviewerReleaseBindingV1) { r.Planner.SourceCommit = strings.Repeat("0", 40) }},
		{"missing config", func(r *KnowledgeReviewerReleaseBindingV1) { r.Planner.ConfigReceiptSHA256 = "" }},
		{"uppercase hex", func(r *KnowledgeReviewerReleaseBindingV1) { r.Auth.ConfigReceiptSHA256 = strings.Repeat("B", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.change(&r)
			e, err := ValidateKnowledgeReviewerReleaseBinding(r, input)
			if !errors.Is(err, ErrKnowledgeReviewerReleaseBinding) || e != (KnowledgeReviewerReleaseBindingEvidenceV1{}) {
				t.Fatal("invalid record accepted")
			}
		})
	}
	for _, bad := range [][]byte{nil, []byte("not PEM"), append([]byte("untrusted prefix\n"), input...), append(append([]byte{}, input...), input...), append(append([]byte{}, input...), []byte("trailing material")...), []byte(strings.Repeat("x", (16<<10)+1))} {
		r := base
		sum := sha256.Sum256(bad)
		r.PEMSHA256 = hex.EncodeToString(sum[:])
		if _, err := ValidateKnowledgeReviewerReleaseBinding(r, bad); !errors.Is(err, ErrKnowledgeReviewerReleaseBinding) {
			t.Fatal("invalid PEM accepted")
		}
	}
}

func TestKnowledgeReviewerReleaseBindingRejectsPrivateWeakAndNonRSA(t *testing.T) {
	key, privatePEM, publicPEM := reviewerKeyPEMs(t)
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{[]byte(privatePEM), pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&weak.PublicKey)}), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER}), pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Headers: map[string]string{"untrusted": "header"}, Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)})} {
		r := syntheticReviewerRelease(t, &key.PublicKey, bad)
		if _, err := ValidateKnowledgeReviewerReleaseBinding(r, bad); !errors.Is(err, ErrKnowledgeReviewerReleaseBinding) {
			t.Fatal("private, weak, wrong-type or header material accepted")
		}
	}
	issuer, err := NewKnowledgeReviewerTokenIssuer("synthetic-auth.test", privatePEM, publicPEM, &reviewerPermissionFixture{})
	if err != nil {
		t.Fatal(err)
	}
	r := syntheticReviewerRelease(t, &key.PublicKey, []byte(publicPEM))
	if e, err := issuer.ValidateReleaseBinding(r, []byte(publicPEM)); err != nil || e.Status != KnowledgeReviewerReleaseSourceOnly {
		t.Fatal(err)
	}
	other, _, otherPEM := reviewerKeyPEMs(t)
	otherRecord := syntheticReviewerRelease(t, &other.PublicKey, []byte(otherPEM))
	if _, err = issuer.ValidateReleaseBinding(otherRecord, []byte(otherPEM)); !errors.Is(err, ErrKnowledgeReviewerReleaseBinding) {
		t.Fatal("signer public mismatch accepted")
	}
	issuer.issuer = "other"
	if _, err = issuer.ValidateReleaseBinding(r, []byte(publicPEM)); !errors.Is(err, ErrKnowledgeReviewerReleaseBinding) {
		t.Fatal("signer issuer mismatch accepted")
	}
	var absent *KnowledgeReviewerTokenIssuer
	if _, err = absent.ValidateReleaseBinding(r, []byte(publicPEM)); !errors.Is(err, ErrKnowledgeReviewerReleaseBinding) {
		t.Fatal("unconfigured signer accepted")
	}
	malformed := &KnowledgeReviewerTokenIssuer{issuer: r.Issuer, key: &rsa.PrivateKey{}}
	if _, err = malformed.ValidateReleaseBinding(r, []byte(publicPEM)); !errors.Is(err, ErrKnowledgeReviewerReleaseBinding) {
		t.Fatal("malformed signer accepted")
	}
}
