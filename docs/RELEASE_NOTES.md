# Release Notes

## v0.1.0-rc.1 — Prerelease

This is the first prerelease candidate for MCP Edge Gateway. It is intended
for manual validation before the `v0.1.0` production release. Do not use this
build for externally exposed deployments without completing the deployment
checklist in `SECURE_DEPLOYMENT_CHECKLIST.md` and validating against your
specific environment.

### What's included

All five implementation phases are complete:

- **Phase 0** — Security baseline: SSRF protection, body/response size limits,
  concurrent request and stream limits, host validation, credential redaction,
  header stripping, tool policy enforcement.
- **Phase 1** — Reloadable config, SQLite state store (WAL, foreign keys,
  migration framework), atomic config writes with timestamped backups.
- **Phase 2** — Local administration: separate admin listener, Argon2id
  password hashing, session/CSRF management, per-IP rate limiting, audit
  events, config editor UI, token management UI.
- **Phase 3** — OAuth resource server: RFC 6750 Bearer token enforcement,
  RFC 9728 protected-resource metadata, token issuance with route audience
  binding, per-tool scope enforcement.
- **Phase 4** — OAuth authorization server: RFC 8414 discovery metadata,
  PKCE S256 authorization code flow, resource indicators, static and dynamic
  client registration, Client ID Metadata Documents, refresh token rotation
  with replay-family revocation, explicit revocation.

### Validated behaviors

The test suite (215 tests, 97%+ line coverage) covers:

- Unauthenticated MCP request rejection (401 with `WWW-Authenticate`)
- Valid, expired, revoked, and wrong-audience token handling
- PKCE S256 enforcement and verifier validation
- Exact redirect URI matching and open redirect rejection
- Authorization-response `iss` parameter (mix-up attack resistance)
- Resource indicator validation and audience binding
- Client ID Metadata Document SSRF and validation failures
- Dynamic client registration validation and rate limiting
- Refresh token rotation, replay detection, and family revocation
- Administration login failure, lockout, and session management
- CSRF rejection and browser security headers
- YAML validation failures that leave the previous config unchanged
- Atomic config replacement and timestamped backup creation
- Credential and token redaction in logs
- Upstream header stripping and response header filtering
- Administration routes absent from the public listener
- Full ChatGPT-compatible OAuth connection flow (discovery → dynamic
  registration → PKCE auth code → token exchange → MCP request → refresh)

### Known residual risks

These risks are accepted for the initial release and documented for operators:

1. **Bearer token theft.** Access tokens are opaque bearer credentials. A
   stolen token is valid until expiry (`accessTokenTtlSeconds`, default 15
   minutes) or explicit revocation. Sender-constrained tokens (DPoP) are a
   future option. Mitigate by keeping expiry short and monitoring for
   unexpected requests in logs.

2. **Compromised Unraid host.** If the host running the gateway is compromised,
   all secrets in `/config` are exposed. The Argon2id password hashes are
   computationally expensive to crack but not impossible. Mitigate by keeping
   the Unraid host patched and access-controlled.

3. **Malicious upstream MCP servers.** The gateway enforces tool call policies
   but does not sanitize tool descriptions or call responses. A malicious or
   compromised upstream could return prompt-injection content in `tools/list`
   responses. Mitigate by only adding trusted upstreams and reviewing tool
   descriptions before granting access.

4. **Prompt injection through MCP tool responses.** Tool call results returned
   by the upstream are forwarded verbatim. If a tool returns attacker-controlled
   content, that content reaches the client without further sanitization.

5. **Config at rest.** `gateway.yaml` contains upstream hostnames and
   configuration but not secrets (tokens are in the SQLite database, passwords
   are hashed). The database at `state/gateway.db` contains hashed credentials
   and token hashes. Restrict filesystem access and back up securely.

6. **Single administrator.** The admin interface supports one administrator
   account. There is no multi-user access control for the administration UI.

7. **Rate limit storage.** Login and registration rate limits are stored in
   SQLite and survive container restarts, but an attacker who can write to
   the database can bypass them. Protect the `/config` directory.

8. **Bootstrap credential window.** The bootstrap credential is printed to
   container logs on first start. Any process with access to container logs
   during the window between start and setup completion could read it. Complete
   setup immediately after first start.

### Breaking changes

None — this is the first release.

### Upgrade notes

For future releases: run migrations automatically on startup. No manual
database migration is required. Back up `state/gateway.db` before upgrading.

### Validating this prerelease

Before promoting `v0.1.0-rc.1` to `v0.1.0`:

1. Deploy from the published image digest (not the mutable `rc` tag).
2. Complete all items in `SECURE_DEPLOYMENT_CHECKLIST.md`.
3. Verify ChatGPT can connect using developer mode against the deployed gateway.
4. Verify the Unraid MCP backend through at minimum: initialize, tools/list,
   an allowed tool call, a blocked tool call, and the SSE transport.
5. Verify the admin UI credential rotation flow end to end.
6. Record accepted residual risks for the deployment.
