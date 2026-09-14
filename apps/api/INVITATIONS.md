# Tenant invitations (local profile)

The implemented AC-07 slice supports tenant-scoped invitation creation, listing,
revocation, and one-time public acceptance. It intentionally does not send email.

## Local operation

Apply the control and tenant-only migrations before starting the API:

```powershell
pnpm --filter @nombramientos/database build
pnpm --filter @nombramientos/database db:migrate:control
pnpm --filter @nombramientos/database db:migrate:tenants
```

`db:migrate:tenants` refuses non-loopback hosts, ports other than the workspace
PostgreSQL 18 port `55432`, non-deterministic tenant database/role names, and a
tenant database whose `tenant_settings` does not match the control-plane route.
It only applies tenant migrations and reconciles runtime grants; it does not
provision, reseed the catalog, or mutate operational round data.

An authenticated tenant principal with `role.manage` can call:

- `POST /v1/invitations` with CSRF and a UUID `Idempotency-Key`.
- `GET /v1/invitations` with CSRF to list non-secret metadata for its session tenant.
- `POST /v1/invitations/{invitationId}/revoke` with CSRF.

In `development` or `test`, the create response contains a 256-bit
`acceptanceToken` only on the first successful request. The database stores only
its SHA-256 digest. Idempotent replay never returns the token again. Treat the
first response as sensitive local access material and do not log or persist it.

The rate-limited public endpoint `POST /v1/invitations/accept` requires that
token, the exact normalized recipient email, a display name, and a strong
password. It stores only an Argon2id password hash, consumes the token once, and
activates only the exact allowlisted roles from the invitation. Unknown, expired,
revoked, consumed, email-mismatched, and cross-tenant attempts share a neutral
public error.

An acceptance that is interrupted after it enters `accepting` is never reclaimed
automatically: automatic lease takeover could let two workers remove each other's
role grants. It remains fail-closed and can be revoked by a tenant manager; the
revocation path removes any invitation-sourced tenant bindings.
Expired or failed rows that retain an interrupted claim remain revocable for the
same cleanup reason; they never create an authenticated session on acceptance.

## Production boundary

Creation fails closed with `INVITATION_DELIVERY_UNAVAILABLE` in `production`.
Before production use, connect an approved external delivery channel that sends
the raw token once without placing it in application logs or durable control data.

Acceptance requires a fresh sign-in and does not create a session automatically.
Invitations containing `CHURCH_ADMIN`, `COMMITTEE_CHAIR`,
`COMMITTEE_SECRETARY`, or `TALLY_CUSTODIAN` are marked MFA-required. Their first
password login creates an `enrollment_only` session with no tenant permissions or
E2EE key grant. The API centrally permits only session inspection, MFA enrollment,
enrollment cancellation/confirmation, and logout until TOTP is confirmed.

Enrollment requires a session authenticated in the previous ten minutes and CSRF.
The TOTP seed is generated with the operating-system CSPRNG, encrypted with
AES-256-GCM at rest, and returned with its `otpauth` URI only in the initial
`no-store` response. Confirmation revokes the old session and recovery-code
generation, creates ten Argon2id-hashed one-use recovery codes, and returns their
plaintext only once. Using a recovery code consumes it transactionally, revokes
other sessions and outstanding MFA challenges, and still does not create or
recover a tenant E2EE key grant.

`COMMITTEE_MEMBER` and `AUDITOR` invitations are not forced by the current policy,
but every authenticated account can opt in from Security settings. Passkeys, an
externally reviewed production identity provider, and an administrative account
recovery ceremony remain separate release requirements.
