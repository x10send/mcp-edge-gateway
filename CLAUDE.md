# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
npm ci

# Start dev server (hot reload via tsx watch)
GATEWAY_CONFIG=./gateway.yaml npm run dev

# Run all quality checks (format, lint, typecheck, test+coverage, build)
npm run check

# Run tests only
npm test

# Run a single test file
node --import tsx --test test/tool-policy.test.ts

# Run tests with coverage (enforces thresholds)
npm run test:coverage

# Type-check without emitting
npm run typecheck

# Format source
npm run format

# Build to dist/
npm run build
```

The `npm run check` pipeline is the gate: format check → lint → typecheck → test+coverage → build. CI runs the same command.

## Architecture

The gateway is a Fastify HTTP proxy that routes path-based MCP streamable HTTP traffic to local backend MCP servers. It is designed to run in Docker behind a Cloudflare Tunnel.

**Module responsibilities:**

- `src/server.ts` — process entrypoint only: loads config, calls `buildApp`, binds the socket, handles SIGTERM/SIGINT. Excluded from coverage because it just wires process lifecycle.
- `src/app.ts` — all application logic: builds the Fastify instance, registers `/health`, `/diagnostics`, and `/.well-known/oauth-protected-resource` (RFC 9728) routes, and for each configured route registers three Fastify routes plus a per-route metadata endpoint. `createProxyHandler` handles OAuth Bearer token enforcement (rejects `access_token` query params, validates tokens via `lookupToken`, checks route audience + required scopes + tool-level scopes), tool-policy enforcement, upstream proxying, and SSE endpoint URL rewriting.
- `src/config.ts` — loads and validates `gateway.yaml`. Exports typed interfaces (`GatewayConfig`, `SecurityConfig`, `RouteConfig`, `ToolPolicyConfig`) used everywhere else.
- `src/tool-policy.ts` — `ToolPolicy` class: evaluates glob-based allow/deny lists. Used in two ways: `findBlockedCall()` rejects `tools/call` requests before they reach the upstream; `filterToolsListPayload()` strips denied tools from `tools/list` JSON responses. SSE streams are never inspected.
- `src/upstream-dispatcher.ts` — creates the undici `Agent` used for all upstream requests. When `allowPrivateUpstreamsOnly: true`, wraps DNS resolution to reject non-private-network addresses (SSRF mitigation).
- `src/config-service.ts` — `ConfigService` wraps config loading with an atomic `reload()` method (throws and leaves current config unchanged if the new file is invalid). The current server wiring requires a restart after config save because registered Fastify routes are not rebuilt in place.
- `src/config-writer.ts` — `writeConfigAtomic(configPath, content)` validates YAML content, writes via temp file + fsync + atomic rename, keeps up to 5 timestamped `.bak` backups of the previous file.
- `src/state.ts` — `StateStore` wraps `node:sqlite` (`DatabaseSync`). `open()` creates the state directory (mode 0700), opens/creates `gateway.db` (mode 0600), runs SQLite PRAGMAs (WAL, foreign keys, synchronous=NORMAL), applies pending migrations in transactions, and runs an integrity check. `close()` closes the database. The `database` getter exposes the handle for admin/OAuth routes. `MIGRATIONS` array is the source of truth for all schema versions; names must be stable across releases.
- `src/oauth-token-store.ts` — opaque OAuth token CRUD: `issueToken` (32-byte random plaintext → SHA-256 hash stored), `lookupToken` (validates hash + not-revoked + not-expired + route audience), `revokeToken` (soft-delete via `revoked_at`), `listTokens`, `tokenStatus`, `hasScope` (space-separated scope membership check).
- `src/oauth-authorization-server.ts` — embedded OAuth authorization server: metadata, static clients, Client ID Metadata Documents, rate-limited dynamic registration, separate resource-owner password login and consent, PKCE S256 authorization codes, resource indicators, refresh rotation with replay-family revocation, and revocation.
- `src/admin-auth.ts` — all authentication primitives: Argon2id password hashing (`@node-rs/argon2`), one-time bootstrap credential (SHA-256 hash stored, timing-safe comparison), session management (32-byte random token → SHA-256 hash in DB), CSRF tokens (24-byte random, session-bound), per-IP login rate limiting (DB-backed, survives restarts), and audit event logging.
- `src/admin-app.ts` — separate Fastify instance for the admin listener (default port 8789). Routes: `GET/POST /admin/setup` (first-run bootstrap), `GET/POST /admin/login`, `POST /admin/logout`, `GET /admin/dashboard`, `GET /admin/config`, `POST /admin/config/preview` (validates YAML via temp file), `POST /admin/config` (saves with session rotation), `GET /admin/tokens`, `GET /admin/tokens/new`, `POST /admin/tokens` (issue — shows plaintext once), `POST /admin/tokens/:id/revoke`. Every response gets security headers (DENY framing, nosniff, no-referrer, CSP, no-store). All state-changing routes require both session auth and CSRF validation. Config save rotates the session token and reports that a gateway restart is required.

**Transport endpoints per configured route:**

Each `path: /prefix` + `upstream: http://backend` entry in `routes[]` causes the gateway to register three endpoints:

| Endpoint           | Methods         | Upstream           | Transport                                       |
| ------------------ | --------------- | ------------------ | ----------------------------------------------- |
| `/prefix/mcp`      | GET POST DELETE | `backend/mcp`      | MCP streamable HTTP                             |
| `/prefix/sse`      | GET             | `backend/sse`      | Legacy HTTP+SSE — rewrites `endpoint` event URL |
| `/prefix/messages` | POST DELETE     | `backend/messages` | Legacy HTTP+SSE messages                        |

**SSE endpoint URL rewriting:** When an upstream SSE response contains an `event: endpoint` event (used by the legacy HTTP+SSE transport to tell clients where to POST messages), the gateway rewrites the URL in the `data:` field from the upstream's internal address to the gateway's own `/prefix/messages` URL. The public URL is derived from the configured `security.publicOrigin`, never from a request header. After the endpoint event is processed, subsequent SSE chunks pass through as raw bytes.

**Request flow:**

```
Incoming request
  → Host header validation (allowedHosts)
  → Concurrent request limit check
  → Reject access_token in query string (400)
  → OAuth: if requireAuth or requiredScopes set → validate Bearer token (401/403)
  → Tool policy: findBlockedCall() → 403 if denied (tools/call only; not applied to GET /sse)
  → Tool scope check: if token auth active and toolScopes configured → 403 if insufficient
  → undici request to upstream (privateLookup enforced)
  → If JSON response: buffer + filterToolsListPayload() + forward
  → If SSE response: acquire stream slot + pipe with lifetime timeout
      └─ If /sse route: rewrite endpoint event URL in stream
  → Otherwise: pipe body directly
```

**Tool policy precedence:** deny always beats allow. Route-level `defaultDenyDangerousTools` overrides global; route allow/deny lists are merged (appended) with global lists.

**Testing approach:** Tests import `buildApp` directly and inject requests via `app.inject()` — no sockets needed. The `sendUpstream` function is injectable via `BuildAppOptions` so tests can mock upstream responses without a real backend. See `test/app.test.ts` for patterns.

## Configuration

`gateway.yaml` (gitignored) is read at startup via `GATEWAY_CONFIG` env var (default `/config/gateway.yaml`) through `ConfigService`. The SQLite state directory is set via `GATEWAY_STATE_DIR` env var (default `/config/state`). Copy `gateway.example.yaml` to start. Real hostnames and IPs must stay in `gateway.yaml` (gitignored) and never in committed files.

Each route entry uses a **base path prefix** (e.g., `/unraid`) and a **base upstream URL** (e.g., `http://unraid-agent.local:8043`). The gateway appends `/mcp`, `/sse`, and `/messages` to both. Paths must not end with `/`, `/mcp`, `/sse`, or `/messages`.

Key security defaults: `allowPrivateUpstreamsOnly: true` (blocks public-internet upstreams at DNS resolution time), `defaultDenyDangerousTools: true` (denies tools matching shell/exec/write/delete/restart/stop/start/reboot/shutdown/update/install), and `requireAuth: false` with the required explicit LAN-development override `insecureAllowUnauthenticatedMcp: true`. `security.publicOrigin` is required and defines canonical public OAuth and rewritten SSE URLs without trusting request headers. Plain HTTP origins require the separate explicit LAN-development override `insecureAllowHttpPublicOrigin: true`.

**OAuth token configuration:** `security.requireAuth: true` enforces a valid Bearer token on all routes. `routes[n].requiredScopes: [scope]` enforces both auth and specific scopes on a single route. `routes[n].tools.toolScopes: { toolName: [scope] }` enforces additional per-tool scopes when auth is active. Bearer tokens are issued/revoked via the admin UI and stored as SHA-256 hashes. Tokens carry a route audience (`routes` field) — a token issued for `/unraid` cannot be used on `/other`. Query-string `access_token` is always rejected (400); only `Authorization: Bearer` is accepted.

## Security Constraints

- Do not commit real hostnames, IPs, tokens, credentials, or machine-specific paths — they belong in gitignored `gateway.yaml` and `.env`.
- `src/server.ts` is excluded from coverage thresholds intentionally — do not add it to `--test-coverage-include` flags.
- Coverage thresholds (90% lines, 75% branches, 90% functions) are applied to the aggregate of all `--test-coverage-include` files: `src/admin-app.ts`, `src/admin-auth.ts`, `src/app.ts`, `src/config.ts`, `src/config-service.ts`, `src/config-writer.ts`, `src/oauth-authorization-server.ts`, `src/oauth-token-store.ts`, `src/state.ts`, `src/tool-policy.ts`, and `src/upstream-dispatcher.ts`. Changes to any of these files must maintain the aggregate thresholds.
- Security-sensitive changes require a regression test.
- The `/health` endpoint intentionally exposes nothing beyond `{ status: "ok" }`. Do not add routes, version, or upstream details to it.
- The `/diagnostics` endpoint is disabled by default; it requires `GATEWAY_DIAGNOSTICS_TOKEN` ≥ 32 chars and Bearer auth. Token comparison uses `timingSafeEqual`.

## Admin App

The admin app runs as a completely separate Fastify instance on `admin.host:admin.port` (default `127.0.0.1:8789`). It is only started when `admin.enabled: true` in config. The public MCP listener (port 8788) never registers any `/admin/*` routes — they 404 by construction.

**First-run flow:** On first start with `admin.enabled: true`, the bootstrap credential (24 bytes base64url) is printed to stdout once. The operator visits `/admin/setup`, enters the credential and a password (≥12 chars), and the admin is ready. The bootstrap token is consumed (one-time only).

**Session/CSRF:** Login issues a session cookie (`mcp_admin_session`, httpOnly, secure by default, sameSite=strict, path=/admin). Each session carries a CSRF token stored in the DB. State-changing routes require both a valid session AND the matching CSRF token in the request body. Session rotation happens on config save.

**Admin config settings (in `gateway.yaml`):** `admin.port` (must differ from 8788), `admin.host` (default 127.0.0.1), `admin.insecureAllowHttpCookies` (default false; LAN-only direct HTTP override), `admin.sessionTtlSeconds` (default 28800), `admin.maxLoginAttemptsPerHour` (default 10), `admin.loginLockoutSeconds` (default 900). Admin config changes require a gateway restart to take effect.

## OAuth Resource Server (Phase 3)

Phase 3 adds RFC 6750 Bearer token enforcement and RFC 9728 protected resource metadata.

**Discovery:** `GET /.well-known/oauth-protected-resource` (root) and `GET /.well-known/oauth-protected-resource/<prefix>/mcp` (path-specific) return the resource metadata document. These endpoints are unauthenticated.

**WWW-Authenticate:** 401 responses include `Bearer realm="MCP Gateway", resource_metadata="<url>"`. 403 responses for insufficient scope include `error="insufficient_scope", scope="<required>"`.

**Token issuance:** Admin UI at `/admin/tokens`. Tokens are 32-byte random base64url strings; only the SHA-256 hash is stored. Plaintext is shown once. Tokens carry optional description, scope, route audience, and expiry.

## OAuth Authorization Server (Phase 4)

When `oauth.enabled: true`, the public listener exposes authorization-server
metadata plus `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, and
`/oauth/register`. OAuth login uses a separate resource-owner password managed
at `/admin/oauth-user`; do not reuse the LAN administration password.

## Current Status

Phases 0–5 are complete. Phase 5 added: full ChatGPT-compatible OAuth flow tests (`test/chatgpt-oauth-flow.test.ts`), protocol-level OAuth regression tests, installation guide (`docs/INSTALLATION.md`), incident-response runbook (`docs/INCIDENT_RESPONSE.md`), release notes with residual risks (`docs/RELEASE_NOTES.md`), and prerelease-safe Docker release CI (skips `latest` tag for prerelease semver). See `docs/SECURE_DEPLOYMENT_CHECKLIST.md` for the full exposure-readiness checklist.
