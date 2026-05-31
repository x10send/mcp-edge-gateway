# MCP Edge Gateway Project Specification

## Objective

Build an open source, Dockerized MCP edge gateway for Unraid. The gateway
provides one external HTTP endpoint and routes path-based MCP streamable HTTP
traffic to local MCP servers such as Unraid Management Agent, Home Assistant,
Hubitat, and Plex.

Public examples use neutral placeholders. Real hostnames, IP addresses, tunnel
details, tokens, and machine-specific mount paths belong only in ignored local
files such as `gateway.yaml` and `.env`.

## Initial Delivery

The first release provides:

- A TypeScript and Node.js Fastify server.
- YAML configuration loaded from `/config/gateway.yaml` by default.
- A `/health` endpoint.
- Route-based `GET`, `POST`, and `DELETE` proxying for MCP streamable HTTP.
- End-to-end header preservation, including `Mcp-Session-Id`.
- Streaming relay for SSE responses.
- Structured Fastify logging.
- Tool allowlist and denylist support with case-insensitive glob patterns.
- Default denial of dangerous tool names containing `shell`, `exec`, `write`,
  `delete`, `restart`, `stop`, `start`, `reboot`, `shutdown`, `update`, or
  `install`.
- Dockerfile, Docker Compose configuration, and Unraid deployment docs.
- Cloudflare Tunnel setup documentation.

## Architecture

`src/server.ts` is the process entrypoint. It loads YAML configuration, builds
the Fastify application, listens on the configured interface, and handles
shutdown signals.

`src/app.ts` constructs the application and proxies configured MCP paths. It is
kept separate from process startup so tests can inject HTTP requests without
binding sockets.

`src/config.ts` validates YAML configuration and rejects invalid or duplicate
routes.

`src/tool-policy.ts` evaluates configured tool rules. Deny rules win over allow
rules. JSON `tools/list` responses are filtered. Denied `tools/call` requests
are rejected before dispatch to an upstream MCP server. SSE responses remain
transparent and are streamed unchanged.

## Configuration Model

```yaml
server:
  host: 0.0.0.0
  port: 8788
  logLevel: info

tools:
  defaultDenyDangerousTools: true
  allow: []
  deny: []

routes:
  - path: /unraid/mcp
    upstream: http://unraid-agent.local:8043/mcp
```

Each route may define its own `tools` block. Route rules are combined with
global rules.

## Quality Rules

Every pull request must pass `npm run check`, which runs:

1. Prettier formatting verification.
2. ESLint static analysis.
3. TypeScript typechecking.
4. Automated tests with coverage thresholds.
5. A production TypeScript build.

CI also builds the Docker image for pushes to `main` and pull requests.

Coverage must remain at or above 90% for lines, 75% for branches, and 90% for
functions across `src/app.ts`, `src/config.ts`, and `src/tool-policy.ts`.
`src/server.ts` is excluded because it only wires configuration, process
signals, and socket startup around the tested application builder.

Proxy behavior changes require tests. Security-sensitive changes require a
regression test. The checked-in suite covers configuration validation, default
tool denial, allowlist and denylist precedence, health reporting, MCP session
header relay, query-string forwarding, SSE streaming, filtered tool discovery,
and pre-dispatch rejection of denied tool calls.

## Deployment Model

The Docker image listens on port `8788`. Docker Compose mounts a local YAML file
at `/config/gateway.yaml`. On Unraid, `.env` may point
`GATEWAY_CONFIG_FILE` at an appdata-managed YAML file.

Cloudflare Tunnel maps a public hostname such as `mcp.example.com` to the
gateway HTTP service. MCP routes must not be cached.

Semantic version tags such as `v0.1.0` publish Docker images to GitHub
Container Registry at `ghcr.io/x10send/mcp-edge-gateway`. Releases publish full,
minor, major, and `latest` tags.

## Next Milestone: Authentication and Local Administration

The next milestone adds ChatGPT-compatible OAuth and a local configuration web
page before additional MCP backends are exposed externally.

### Public MCP Listener

The public MCP listener remains on port `8788`. Cloudflare Tunnel may forward
traffic to this listener. It serves:

- `/health`
- Configured MCP proxy routes such as `/unraid/mcp`
- OAuth discovery and protocol endpoints required by remote MCP clients

MCP routes require a valid access token after OAuth is enabled. The gateway
must validate tokens before forwarding traffic to any local backend.

### OAuth Authorization Layer

The gateway will implement an embedded OAuth authorization layer for small
self-hosted deployments. The implementation must support the MCP authorization
flow expected by remote clients, including ChatGPT developer mode:

- OAuth authorization server metadata.
- OAuth protected resource metadata for MCP endpoints.
- `WWW-Authenticate` discovery headers on unauthenticated MCP requests.
- Authorization code flow with PKCE using `S256`.
- Client ID Metadata Documents as the preferred registration approach when
  client support is available.
- Static preregistration for known clients.
- Dynamic client registration as a compatibility fallback when static
  credentials or Client ID Metadata Documents are not supplied.
- Short-lived access tokens and revocable refresh tokens.
- OAuth resource indicators and token resource binding so tokens cannot be
  replayed against unrelated MCP routes.
- Configurable scopes mapped to routes and tool policies.
- `403` insufficient-scope challenges suitable for step-up authorization.
- Explicit login and consent before issuing tokens.
- HTTPS for externally reachable OAuth endpoints and redirect URI validation.
- Authorization-response issuer identifiers for mix-up attack resistance.

OAuth secrets, signing keys, refresh tokens, and administrator credentials must
not be stored in the public YAML example or logged. Persistent secrets belong
under `/config` with restrictive filesystem permissions.

The initial implementation targets a single-administrator home deployment.
Support for delegating authentication to an external identity provider may be
added later without removing the embedded option. OAuth protocol primitives
and token cryptography must use maintained libraries rather than custom
implementations.

### Security Posture

No design can be made literally bulletproof. The release target is a
deny-by-default gateway with documented residual risk, automated security
regression tests, and a threat model reviewed before external exposure.

The production posture is:

- OAuth is mandatory for externally reachable MCP routes. A deployment cannot
  enable a public MCP route with authentication disabled without an explicit
  insecure-development override.
- The administration listener is disabled by default, never mounted on the
  public listener, and never routed through Cloudflare Tunnel.
- Public health responses expose liveness only. They do not list internal
  routes, upstream addresses, version details, or authentication state.
- Tool policies are deny-first. Explicit deny rules always win over allow
  rules, and dangerous defaults remain enabled unless a local administrator
  deliberately overrides them.
- Requests fail closed when configuration, token validation, state storage, or
  policy evaluation fails.
- Access tokens are audience-restricted opaque bearer tokens. Sender-constrained
  tokens such as DPoP are a future hardening option if ChatGPT client support
  and operational complexity justify them.
- Every release documents known residual risks, especially bearer-token theft,
  a compromised Unraid host, malicious upstream MCP servers, prompt injection,
  and an attacker with access to `/config`.

### Threat Model

The design must address:

- Internet attackers probing the public MCP and OAuth endpoints.
- Stolen access tokens, refresh tokens, authorization codes, cookies, or
  bootstrap credentials.
- OAuth mix-up, open redirect, CSRF, clickjacking, credential stuffing, and
  brute-force attempts.
- Dynamic client registration abuse and malicious Client ID Metadata Document
  URLs.
- SSRF, DNS rebinding, and local-network discovery through administrator-added
  upstream URLs.
- Header spoofing when TLS terminates at Cloudflare Tunnel or another reverse
  proxy.
- Secrets appearing in logs, errors, metrics, backups, browser history, or
  support bundles.
- Prompt injection and unexpected tool selection after a trusted client is
  authorized.
- A malicious or compromised local MCP backend returning unsafe content.
- Corrupt state databases, interrupted writes, failed migrations, and
  restoration of stale credentials from backup.

The initial deployment does not attempt to defend against a fully compromised
Unraid host or an attacker who can read the mounted `/config` directory. Those
conditions require host remediation and credential rotation.

### Credential Storage

`gateway.yaml` contains non-secret configuration and references to secret
records. It must not contain plaintext passwords, tokens, client secrets, or
signing keys.

Persistent sensitive state lives under `/config`:

```text
/config/gateway.yaml
/config/secrets/
/config/state/
```

The container creates secret directories with mode `0700` and secret files
with mode `0600`. The initial implementation stores OAuth state in a
permissions-restricted SQLite database under `/config/state`. Encryption at
rest may be added later, but it does not replace restrictive host filesystem
permissions and Unraid appdata backup controls.

Database access must use parameterized statements, transactions, schema
migrations, integrity checks, and bounded backup retention. Backups containing
sensitive state must receive the same permissions and retention policy as the
active database. Restore documentation must require revoking credentials issued
after the restored backup.

Credential types are handled separately:

- Administration passwords are hashed with a maintained password-hashing
  library using Argon2id. Plaintext passwords are never stored.
- The one-time administration bootstrap credential is randomly generated,
  stored as a hash, consumed once, and never reused as a normal password.
- OAuth resource-owner credentials are separate from administration
  credentials. A user should not submit the LAN administration password to the
  public OAuth login page.
- Dynamic OAuth clients using PKCE are treated as public clients and do not
  receive a client secret unless the protocol requires one for a specific
  confidential-client configuration.
- Static confidential-client secrets, if supported later, are stored as hashes
  and shown only once when created.
- Authorization codes are short-lived, single-use records stored as hashes.
- Access tokens are high-entropy opaque bearer tokens stored as hashes and
  checked before every proxied MCP request.
- Refresh tokens are high-entropy opaque tokens stored as hashes, rotated on
  use, revocable, and protected against reuse by revoking the associated token
  family when replay is detected.
- Cookies, authorization headers, tokens, codes, credentials, and signing keys
  are redacted from logs and audit event details.

Opaque tokens are preferred initially because they provide straightforward
revocation for a single-instance home gateway. If signed access tokens are
added later, signing keys must live under `/config/secrets`, support rotation,
and never appear in YAML or logs.

### Local Administration Listener

The configuration web page runs on a separate listener, default port `8789`.
It must not be served from the tunnel-facing listener and must not be included
in Cloudflare Tunnel routing.

The administration service will:

- Require administrator authentication.
- Use secure, HTTP-only, same-site cookies with session rotation after login.
- Require CSRF protection for state-changing requests.
- Set anti-clickjacking, content security, referrer, and MIME-sniffing headers.
- Rate-limit login and bootstrap attempts and record lockout audit events.
- Expose a form for server settings, MCP backend routes, and tool policies.
- Validate changes using the same config parser used at process startup.
- Write `/config/gateway.yaml` atomically only after validation succeeds.
- Keep a timestamped backup before replacing a valid config file.
- Redact stored secrets from responses and logs.
- Show whether a restart or configuration reload is required.
- Record audit events for configuration and authentication changes.

The Docker deployment must mount `/config` read-write when administration is
enabled. For deployments that manage YAML manually, the administration service
may remain disabled and `/config/gateway.yaml` may remain read-only.

Binding the administration listener is configurable. Documentation must
recommend LAN-only exposure enforced by Docker port publishing and host
firewall rules. Binding to a LAN interface is not a substitute for
administrator authentication.

The administration listener is disabled by default until explicitly enabled in
the local deployment configuration. Its first-run bootstrap flow must require a
one-time setup credential and must not create a default password.

### Network and Proxy Boundaries

- Public URLs are configured explicitly. Host and forwarded headers do not
  define OAuth issuers, redirect origins, or metadata URLs.
- Reverse-proxy trust is disabled by default and may be enabled only for
  configured proxy addresses. Forwarded headers from untrusted peers are
  ignored.
- Public OAuth endpoints require HTTPS at the configured external origin.
- MCP upstream URLs use an explicit allowlist. The administrator UI must warn
  before allowing loopback, link-local, multicast, metadata-service, or public
  Internet targets.
- Upstream redirects are not followed automatically.
- Hop-by-hop headers are stripped. Sensitive OAuth and administrator headers
  are never forwarded to MCP upstreams.
- Request bodies, response headers, timeouts, concurrent streams, and SSE
  connection lifetimes are bounded.
- Cloudflare caching is disabled for MCP, OAuth, and administration paths.

### Current Pre-Exposure Blockers

The `v0.1.0` image is a development baseline and must not be exposed to
untrusted clients. The current implementation still has known gaps:

- `/health` lists configured MCP route paths.
- Fastify currently uses broad `trustProxy: true`.
- Incoming `Authorization` headers are not yet removed before upstream proxy
  dispatch.
- Request body limits, upstream timeouts, response limits, concurrent stream
  limits, and SSE lifetime limits are not configured.
- Upstream URL validation checks protocol syntax only and does not defend
  against SSRF, DNS rebinding, or redirects.
- OAuth authentication and scope enforcement are not implemented.
- The runtime container has not yet switched to an unprivileged user or a
  read-only root filesystem deployment profile.
- CI does not yet run dependency auditing, secret scanning, static security
  analysis, or container vulnerability scanning.

These items are Gate 0 work. Do not configure Cloudflare Tunnel access to MCP
routes until all Gate 0 blockers and the OAuth gates are complete.

### Exposure Readiness Checklist

External MCP exposure is allowed only when all items are true:

- Gates 0 through 5 are complete and CI is green.
- OAuth discovery, authorization, token, refresh, revocation, scope, and
  negative-path protocol tests pass.
- The public listener exposes no administration routes or internal diagnostics.
- The administration listener is either disabled or published only to a
  reviewed LAN address.
- Cloudflare Tunnel forwards only the public listener and does not cache MCP or
  OAuth paths.
- Trusted-proxy configuration matches the deployed tunnel path.
- At least one narrow read-only route policy has been reviewed manually.
- Dangerous tool defaults remain enabled.
- Backup, restore, credential rotation, and incident response procedures have
  been tested.
- The deployed image is referenced by digest or a verified provenance
  attestation, not only by a mutable tag.
- A release security review records accepted residual risks.

If any item fails, the deployment remains LAN-only.

### Implementation Sequence

#### Gate 0: Security Baseline

1. Maintain the checked-in deployment security checklist and keep `v0.1.0`
   marked as development-only.
2. Remove route names from the public `/health` response.
3. Add a separate authenticated diagnostic endpoint for internal route status.
4. Strip `Authorization`, cookies, OAuth headers, and proxy-only headers before
   dispatching to upstream MCP servers.
5. Add configurable request body limits.
6. Add upstream connect, headers, body, and idle timeouts.
7. Add bounded JSON response buffering and response-header size limits.
8. Add concurrent request, concurrent SSE stream, and SSE lifetime limits.
9. Replace broad proxy trust with an explicit trusted-proxy configuration.
10. Reject unconfigured hostnames and derive public URLs only from explicit
    configuration.
11. Run the runtime image as an unprivileged user.
12. Add a read-only root filesystem deployment profile with writable `/config`
    only when required.
13. Add structured log redaction tests for headers, cookies, tokens, and
    secrets.
14. Add dependency auditing, secret scanning, static security analysis, and
    container vulnerability scanning to CI.
15. Add Dependabot updates for npm, Docker base images, and GitHub Actions.
16. Add an SBOM and GitHub artifact provenance attestation to container
    releases.
17. Document digest-pinned image deployment and attestation verification.
18. Configure protected `main` branch rules requiring CI before merge.

#### Gate 1: Configuration State

1. Refactor configuration loading into a reloadable configuration service.
2. Split public configuration from secret references.
3. Add SQLite state initialization, migrations, integrity checks, and
   permissions verification.
4. Add atomic YAML writes using temporary files, filesystem sync, rename, and
   bounded timestamped backups.
5. Add restore documentation and credential-rotation requirements.
6. Add upstream URL validation, redirect rejection, and SSRF-focused tests.

#### Gate 2: Local Administration

1. Add a separate administration application and listener.
2. Keep the administration listener disabled by default.
3. Add one-time bootstrap credential generation and consumption.
4. Add Argon2id administrator password storage.
5. Add authenticated sessions, secure cookie flags, expiration, and rotation.
6. Add CSRF defenses and browser security headers.
7. Add login throttling, lockout behavior, and audit events.
8. Add forms for routes, upstreams, and tool policies.
9. Add validation previews, atomic save, backup, and reload status.
10. Verify administration routes are unreachable from the public listener.

#### Gate 3: OAuth Resource Server

1. Define canonical public resource URIs for each externally reachable MCP
   route.
2. Add protected-resource metadata at root and path-specific well-known URLs.
3. Add `401` `WWW-Authenticate` responses with resource metadata and minimal
   scopes.
4. Add opaque access-token issuance, hashing, expiration, revocation, and
   audience validation.
5. Reject tokens in query strings and prevent token passthrough to upstreams.
6. Add route-level and tool-level scope evaluation.
7. Add `403` insufficient-scope responses for step-up authorization.

#### Gate 4: OAuth Authorization Server

1. Add authorization-server metadata with explicit issuer and HTTPS endpoints.
2. Add authorization-response issuer identifiers for mix-up resistance.
3. Add authorization code flow with exact redirect URI matching.
4. Require PKCE `S256` and single-use short-lived authorization codes.
5. Add resource-indicator validation on authorization and token requests.
6. Add static client preregistration.
7. Add Client ID Metadata Document support with HTTPS-only fetching, SSRF
   defenses, redirect rejection, response size limits, timeouts, and caching.
8. Add rate-limited dynamic client registration as a compatibility fallback.
9. Add refresh-token rotation, replay-family revocation, and token revocation.
10. Add explicit login and consent screens with CSRF and clickjacking defenses.

#### Gate 5: Integration and Release

1. Run protocol-level OAuth tests against all metadata and token endpoints.
2. Add end-to-end tests for ChatGPT-compatible OAuth connection behavior.
3. Validate Cloudflare Tunnel forwarding and trusted-proxy configuration.
4. Validate the Unraid MCP backend through initialize, session, list, allowed
   call, blocked call, and SSE flows.
5. Document secure Unraid installation, backup, restore, and credential
   rotation.
6. Add an incident-response runbook for token theft, host compromise, stale
   restore, and malicious upstream discovery.
7. Add release notes with known residual risks.
8. Publish a prerelease image for manual validation before promoting `latest`.

### Security Tests

Authentication and administration changes require regression coverage for:

- Unauthenticated MCP request rejection.
- Valid and expired access tokens.
- Access tokens with the wrong audience or supplied in a query string.
- Route and tool-scope enforcement.
- PKCE validation.
- Exact redirect URI validation and open redirect rejection.
- Authorization-response issuer identifiers.
- OAuth resource-indicator validation.
- Client ID Metadata Document SSRF and validation failures.
- Dynamic client registration validation.
- Dynamic client registration rate limits.
- Refresh-token rotation, reuse detection, family revocation, and explicit
  revocation.
- Administration login failure and lockout behavior.
- CSRF rejection and browser security headers.
- YAML validation failures that leave the previous file untouched.
- Atomic config replacement and backup creation.
- Secret redaction in API responses and logs.
- Reverse-proxy spoofing and untrusted forwarded headers.
- Upstream URL SSRF, redirect, timeout, and size-limit failures.
- Confirmation that administration routes are absent from the public listener.

## Roadmap

### Phase 1: Minimal Gateway

- Complete the initial delivery described above.
- Validate against the Unraid Management Agent.
- Validate container builds through GitHub Actions.

### Phase 2: OAuth and Local Administration

- Complete Gates 0 through 5 in order.

### Phase 3: Backend Expansion

- Add local route configuration for Home Assistant, Hubitat, and Plex MCP
  servers as they become available.
- Add backend-specific compatibility tests where behavior differs.
- Add operational documentation for logging and troubleshooting.

### Phase 4: Hardening

- Add request timeouts, body-size limits, and configurable upstream retry
  behavior where MCP semantics permit it.
- Add metrics and structured audit events for denied calls.
- Evaluate DPoP sender-constrained access tokens when client support is
  practical.

## References

- [OpenAI ChatGPT developer mode](https://platform.openai.com/docs/guides/developer-mode)
- [OpenAI remote MCP server guide](https://platform.openai.com/docs/mcp/)
- [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
