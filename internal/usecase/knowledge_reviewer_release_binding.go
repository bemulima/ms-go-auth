package usecase

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const KnowledgeReviewerReleaseBindingSchemaV1 = "knowledge-reviewer-release-binding.v1"
const KnowledgeReviewerReleaseSourceOnly = "SOURCE_ONLY_VALIDATED_RUNTIME_UNBOUND"

var ErrKnowledgeReviewerReleaseBinding = errors.New("knowledge reviewer release binding invalid or unbound")

// These are source-evidence pins, not authenticated deployment or owner approval.
type KnowledgeReviewerReleaseSourceV1 struct {
	SourceCommit        string `json:"source_commit"`
	ConfigReceiptSHA256 string `json:"config_receipt_sha256"`
	PublicSPKISHA256    string `json:"public_spki_sha256"`
	Issuer              string `json:"issuer"`
}

type KnowledgeReviewerReleaseBindingV1 struct {
	Schema         string                           `json:"schema"`
	Issuer         string                           `json:"issuer"`
	PublicKeyOwner string                           `json:"public_key_owner"`
	PEMSHA256      string                           `json:"pem_sha256"`
	SPKISHA256     string                           `json:"spki_sha256"`
	Algorithm      string                           `json:"algorithm"`
	Auth           KnowledgeReviewerReleaseSourceV1 `json:"auth"`
	Planner        KnowledgeReviewerReleaseSourceV1 `json:"planner"`
}

type KnowledgeReviewerReleaseBindingEvidenceV1 struct {
	Status      string `json:"status"`
	Issuer      string `json:"issuer"`
	PEMSHA256   string `json:"pem_sha256"`
	SPKISHA256  string `json:"spki_sha256"`
	RSABits     int    `json:"rsa_bits"`
	PEMEncoding string `json:"pem_encoding"`
}

// ValidateKnowledgeReviewerReleaseBinding performs bounded offline public-key
// consistency checks only. No caller-provided record can grant runtime authority.
// Empty/missing real artifacts fail closed; there is no default issuer or key.
func ValidateKnowledgeReviewerReleaseBinding(record KnowledgeReviewerReleaseBindingV1, publicPEM []byte) (KnowledgeReviewerReleaseBindingEvidenceV1, error) {
	evidence, _, err := validateKnowledgeReviewerReleaseBinding(record, publicPEM)
	return evidence, err
}

// ValidateReleaseBinding compares an already-configured issuer's public key and
// issuer with the source record. It neither loads private material nor signs a
// token. Even a match remains runtime-unbound source evidence.
func (issuer *KnowledgeReviewerTokenIssuer) ValidateReleaseBinding(record KnowledgeReviewerReleaseBindingV1, publicPEM []byte) (KnowledgeReviewerReleaseBindingEvidenceV1, error) {
	evidence, key, err := validateKnowledgeReviewerReleaseBinding(record, publicPEM)
	if err != nil || issuer == nil || issuer.key == nil || issuer.key.N == nil || issuer.issuer != record.Issuer || key.N.Cmp(issuer.key.N) != 0 || key.E != issuer.key.E {
		return KnowledgeReviewerReleaseBindingEvidenceV1{}, ErrKnowledgeReviewerReleaseBinding
	}
	return evidence, nil
}

func validateKnowledgeReviewerReleaseBinding(record KnowledgeReviewerReleaseBindingV1, publicPEM []byte) (KnowledgeReviewerReleaseBindingEvidenceV1, *rsa.PublicKey, error) {
	fail := func() (KnowledgeReviewerReleaseBindingEvidenceV1, *rsa.PublicKey, error) {
		return KnowledgeReviewerReleaseBindingEvidenceV1{}, nil, ErrKnowledgeReviewerReleaseBinding
	}
	if record.Schema != KnowledgeReviewerReleaseBindingSchemaV1 || record.PublicKeyOwner != "ms-go-auth" || record.Algorithm != "RS256" || !validReleaseIssuer(record.Issuer) || !validReleaseHex(record.PEMSHA256, 32) || !validReleaseHex(record.SPKISHA256, 32) || !validReleaseSource(record.Auth, record) || !validReleaseSource(record.Planner, record) || len(publicPEM) == 0 || len(publicPEM) > 16<<10 {
		return fail()
	}
	fileDigest := sha256.Sum256(publicPEM)
	if hex.EncodeToString(fileDigest[:]) != record.PEMSHA256 {
		return fail()
	}
	trimmed := bytes.TrimSpace(publicPEM)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN PUBLIC KEY-----")) && !bytes.HasPrefix(trimmed, []byte("-----BEGIN RSA PUBLIC KEY-----")) {
		return fail()
	}
	if bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 || bytes.Count(trimmed, []byte("-----END ")) != 1 {
		return fail()
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return fail()
	}
	var key *rsa.PublicKey
	switch block.Type {
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fail()
		}
		var ok bool
		key, ok = parsed.(*rsa.PublicKey)
		if !ok {
			return fail()
		}
	case "RSA PUBLIC KEY":
		var err error
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return fail()
		}
	default:
		return fail()
	}
	if key == nil || key.N == nil || key.N.BitLen() < 2048 || key.E < 3 || key.E%2 == 0 {
		return fail()
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fail()
	}
	fingerprint := sha256.Sum256(der)
	if hex.EncodeToString(fingerprint[:]) != record.SPKISHA256 {
		return fail()
	}
	return KnowledgeReviewerReleaseBindingEvidenceV1{Status: KnowledgeReviewerReleaseSourceOnly, Issuer: record.Issuer, PEMSHA256: record.PEMSHA256, SPKISHA256: record.SPKISHA256, RSABits: key.N.BitLen(), PEMEncoding: block.Type}, key, nil
}

func validReleaseSource(source KnowledgeReviewerReleaseSourceV1, record KnowledgeReviewerReleaseBindingV1) bool {
	return validReleaseHex(source.SourceCommit, 20) && validReleaseHex(source.ConfigReceiptSHA256, 32) && source.PublicSPKISHA256 == record.SPKISHA256 && source.Issuer == record.Issuer
}
func validReleaseHex(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size && value == strings.ToLower(value) && value != strings.Repeat("0", size*2)
}
func validReleaseIssuer(value string) bool {
	if value == "" || len(value) > 255 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}
