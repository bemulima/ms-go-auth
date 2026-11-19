package domain

import "context"

// CAT49 registration is a dedicated disposable operator receipt, never a
// generic signup or a credential that can issue tokens before activation.
type CAT49RegistrationReceipt struct {
	Schema        string `json:"schema"`
	RunID         string `json:"run_id"`
	RequestID     string `json:"request_id"`
	PrincipalID   string `json:"principal_id"`
	AuthDatabase  string `json:"auth_database"`
	IntentDigest  string `json:"intent_digest"`
	ReceiptDigest string `json:"receipt_digest"`
	Signature     string `json:"signature"`
}

type CAT49ReviewerRegistration struct {
	Receipt      CAT49RegistrationReceipt
	Email        string
	Password     string
	PasswordHash string
}

type CAT49GrantReceipt struct {
	Schema            string `json:"schema"`
	RunID             string `json:"run_id"`
	RequestID         string `json:"request_id"`
	PrincipalID       string `json:"principal_id"`
	AuthReceiptDigest string `json:"auth_receipt_digest"`
	Role              string `json:"role"`
	Operator          string `json:"operator"`
	AppliedAt         string `json:"applied_at"`
	ReceiptDigest     string `json:"receipt_digest"`
	Signature         string `json:"signature"`
}

type CAT49ReviewerActivation struct {
	PrincipalID             string
	RequestID               string
	GrantReceiptDigest      string
	ActivationReceiptDigest string
}

type CAT49ReviewerOperatorStore interface {
	RegisterCAT49Reviewer(context.Context, CAT49ReviewerRegistration) (bool, error)
	ReadCAT49Registration(context.Context, string) (CAT49RegistrationReceipt, error)
	ActivateCAT49Reviewer(context.Context, CAT49ReviewerActivation) (bool, error)
}
