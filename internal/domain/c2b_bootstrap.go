package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const C2BMentorID = "01a58012-c6df-58a4-b1ac-0f646d7f47c5"
const C2BLearnerID = "fab713c1-218e-49cb-8e57-7bc9bf8606a8"
const C2BRun = "c2b20261016"
const C2BInstance = "8ada3ddb-c548-4991-9d44-51677c5ebff3"
const C2BSubmission = "b332012c-daaa-49fe-bb37-07cd16e3e4ab"

type C2BIntent struct {
	Schema     string `json:"schema"`
	Run        string `json:"run_id"`
	Operation  string `json:"operation_id"`
	Principal  string `json:"principal_id"`
	Email      string `json:"email"`
	Role       string `json:"role"`
	Instance   string `json:"task_instance_id"`
	Submission string `json:"submission_id"`
}
type C2BSignedIntent struct {
	Schema    string `json:"schema"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type C2BReceipt struct {
	Schema       string    `json:"schema"`
	IntentDigest string    `json:"intent_digest"`
	Intent       C2BIntent `json:"intent"`
}

func C2BHash(raw []byte) string { s := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(s[:]) }
func C2BActor(actor string) (C2BIntent, error) {
	var id, role string
	switch actor {
	case "mentor":
		id = C2BMentorID
		role = "mentor"
	case "learner":
		id = C2BLearnerID
		role = "student"
	default:
		return C2BIntent{}, fmt.Errorf("actor outside fixed allowlist")
	}
	s := sha256.Sum256([]byte(C2BRun + ":" + id))
	s[6] = (s[6] & 15) | 80
	s[8] = (s[8] & 63) | 128
	h := hex.EncodeToString(s[:16])
	op := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	return C2BIntent{Schema: "c2b-bootstrap-intent.v1", Run: C2BRun, Operation: op, Principal: id, Email: actor + "+" + C2BRun + "@verification.invalid", Role: role, Instance: C2BInstance, Submission: C2BSubmission}, nil
}
func (i C2BIntent) Valid() bool {
	actor := "mentor"
	if i.Principal == C2BLearnerID {
		actor = "learner"
	}
	expected, e := C2BActor(actor)
	return e == nil && expected == i
}
func (i C2BIntent) Digest() string { b, _ := json.Marshal(i); return C2BHash(b) }
func C2BReceiptFor(i C2BIntent) C2BReceipt {
	return C2BReceipt{Schema: "c2b-rbac-bootstrap-receipt.v1", IntentDigest: i.Digest(), Intent: i}
}
func (r C2BReceipt) Valid() bool { return r == C2BReceiptFor(r.Intent) && r.Intent.Valid() }
