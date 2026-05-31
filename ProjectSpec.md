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
- Authorization code flow with PKCE.
- Dynamic client registration when static client credentials are not supplied.
- Short-lived access tokens and revocable refresh tokens.
- OAuth resource indicators and token resource binding so tokens cannot be
  replayed against unrelated MCP routes.
- Configurable scopes mapped to routes and tool policies.
- Explicit login and consent before issuing tokens.
- HTTPS for externally reachable OAuth endpoints and redirect URI validation.

OAuth secrets, signing keys, refresh tokens, and administrator credentials must
not be stored in the public YAML example or logged. Persistent secrets belong
under `/config` with restrictive filesystem permissions.

The initial implementation targets a single-administrator home deployment.
Support for delegating authentication to an external identity provider may be
added later without removing the embedded option. OAuth protocol primitives
and token cryptography must use maintained libraries rather than custom
implementations.

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
  use, and revocable.
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

### Implementation Sequence

1. Refactor configuration loading into a reloadable configuration service.
2. Add validated atomic YAML writes, backups, and secret-file handling.
3. Add the separate administration listener, bootstrap flow, login, and
   configuration forms.
4. Add OAuth metadata, `401` discovery responses, client registration,
   authorization, token, refresh, and revocation endpoints.
5. Enforce route and tool scopes before proxy dispatch.
6. Add an end-to-end ChatGPT developer mode connection test and deployment
   documentation.

### Security Tests

Authentication and administration changes require regression coverage for:

- Unauthenticated MCP request rejection.
- Valid and expired access tokens.
- Route and tool-scope enforcement.
- PKCE validation.
- Dynamic client registration validation.
- Refresh-token rotation and revocation.
- Administration login failure and lockout behavior.
- YAML validation failures that leave the previous file untouched.
- Atomic config replacement and backup creation.
- Secret redaction in API responses and logs.
- Confirmation that administration routes are absent from the public listener.

## Roadmap

### Phase 1: Minimal Gateway

- Complete the initial delivery described above.
- Validate against the Unraid Management Agent.
- Validate container builds through GitHub Actions.

### Phase 2: OAuth and Local Administration

- Add the embedded ChatGPT-compatible OAuth authorization layer.
- Add scopes for MCP routes and tool policies.
- Add the separate LAN-only administration listener and authenticated web UI.
- Add atomic YAML configuration writes, backup handling, and secret storage.
- Add authentication, authorization, and administration regression tests.
- Validate OAuth connection setup from ChatGPT developer mode.

### Phase 3: Backend Expansion

- Add local route configuration for Home Assistant, Hubitat, and Plex MCP
  servers as they become available.
- Add backend-specific compatibility tests where behavior differs.
- Add operational documentation for logging and troubleshooting.

### Phase 4: Hardening

- Add request timeouts, body-size limits, and configurable upstream retry
  behavior where MCP semantics permit it.
- Add metrics and structured audit events for denied calls.
- Add container image scanning.

## References

- [OpenAI ChatGPT developer mode](https://platform.openai.com/docs/guides/developer-mode)
- [OpenAI remote MCP server guide](https://platform.openai.com/docs/mcp/)
- [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
