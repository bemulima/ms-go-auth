# Reviewer release binding: source-only validation

`ValidateKnowledgeReviewerReleaseBinding` checks an explicit public artifact and
source record offline. It reads no files, configuration, environment, key store
or network. It does not install a key, issue tokens, authenticate an owner or
enable runtime. Existing JWT, config and HTTP contracts remain unchanged.

The real Auth public artifact is currently absent: **UNBOUND**. `lw-auth` is a
source configuration candidate requiring owner acceptance, not an accepted
issuer. No fallback or generated key fills this gap. Test keys are synthetic
in-memory fixtures and must never be used as release bindings.

The record schema is `knowledge-reviewer-release-binding.v1`:

```json
{
  "schema": "knowledge-reviewer-release-binding.v1",
  "issuer": "<explicit owner-proposed issuer>",
  "public_key_owner": "ms-go-auth",
  "pem_sha256": "<lowercase SHA256 of exact public PEM bytes>",
  "spki_sha256": "<lowercase SHA256 of canonical DER SubjectPublicKeyInfo>",
  "algorithm": "RS256",
  "auth": {
    "source_commit": "<full lowercase Git commit>",
    "config_receipt_sha256": "<exact public configuration evidence hash>",
    "public_spki_sha256": "<same canonical public-key fingerprint>",
    "issuer": "<same explicit issuer>"
  },
  "planner": {
    "source_commit": "<full lowercase Git commit>",
    "config_receipt_sha256": "<exact public configuration evidence hash>",
    "public_spki_sha256": "<same canonical public-key fingerprint>",
    "issuer": "<same explicit issuer>"
  }
}
```

Issuer bytes must be nonempty, canonical and at most 255 UTF-8 bytes, matching
the existing Planner verifier boundary rather than introducing a broader issuer.
The public artifact accepts exactly one PKIX `PUBLIC KEY` or PKCS1 `RSA PUBLIC KEY`
PEM block, without headers or other non-whitespace material, at most 16 KiB.
The parsed RSA key must be at least 2048 bits. Both encodings normalize through
`x509.MarshalPKIXPublicKey`; their SPKI fingerprint is identical while their
exact PEM file hashes differ. Private keys, certificates and non-RSA keys fail
closed. Missing/zero pins, changed issuer, source/config/key mismatch and
oversized/malformed artifacts return a fixed error without input details.

The result is always `SOURCE_ONLY_VALIDATED_RUNTIME_UNBOUND`. Caller-provided
commit/config hashes prove consistency only; they do not prove that artifacts
exist, were reviewed, installed or accepted. A procedural decision string cannot
change this result. The caller must independently verify referenced artifacts
and exact build/config identities through the existing authorized workflow.

`KnowledgeReviewerTokenIssuer.ValidateReleaseBinding` additionally compares the
already-configured issuer and its public RSA N/E with this artifact. It loads no
private material and creates no signatures. A match still does not prove which
build is deployed or that Planner has configured that key. Existing signer and
Planner verifier constructors retain their current security responsibilities.

To complete BIND-03, the owner must separately accept the exact issuer, real
Auth-owned public PEM/file hash/SPKI fingerprint, and Auth/Planner source and
configuration evidence. The artifact reader must enforce its existing
descriptor-bound ownership/mode/no-follow/identity checks before passing bytes.
No new JWKS endpoint, runtime route, credentials or acceptance authority is
created here. Deployment and signature verification against actual runtime
remain separate authorized acceptance gates; this source scope runs neither.
