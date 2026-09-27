# AUTH_USER_RBAC_PROVISIONING_CONTRACT_V1

Status: frozen for signup completion.

## Owners and identity

Auth owns orchestration. User owns the user and profile projection. RBAC owns
the principal-role assignment.

The Auth user identifier is the canonical principal identifier. Auth passes
that unchanged as the User projection identifier and the RBAC principal
identifier.

The canonical signup role key is `student`. It is the RBAC key and is accepted
by Student through its normal role normalization.

## Successful signup invariant

Auth may report a successful final signup only after all of these operations
have succeeded synchronously:

1. identity verification has succeeded;
2. the Auth user exists;
3. `user.create-user` has acknowledged durable User projection creation; and
4. `rbac.assign-role` has acknowledged the canonical `student` assignment and
   `rbac.checkRole` confirms it.

Token and session issuance happen only after that invariant holds. The User
creation acknowledgement is the User service's durable read-after-create
boundary; the RBAC check is the normal production role-read boundary.

## Failure invariant

An error, timeout, negative acknowledgement, or failed role check from either
provisioning dependency prevents successful signup completion and token/session
issuance. Auth may retain the verified identity and local Auth user as a
recoverable partial state. It must not compensate by deleting remote state or
silently treat an incomplete actor as successful.

## Idempotency and recovery

Signup completion retries use the same canonical principal identifier. User
creation and role assignment are idempotent at their owning services.

* If User creation succeeded and RBAC assignment failed, retrying repeats
  User creation safely and repairs the role assignment.
* If RBAC assignment succeeded while User creation did not become visible,
  retrying creates the User projection and repeats the role assignment safely.
* If both completed but the response was lost, retrying converges on the same
  Auth user, User projection, and role assignment.

No distributed transaction, manual database repair, fabricated actor, or
Teacher-specific bypass is part of this contract.
