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
- `src/app.ts` — all application logic: builds the Fastify instance, registers `/health` and `/diagnostics` routes, and for each configured route registers three Fastify routes (see transport endpoints below). `createProxyHandler` handles tool-policy enforcement, upstream proxying, and SSE endpoint URL rewriting.
- `src/config.ts` — loads and validates `gateway.yaml`. Exports typed interfaces (`GatewayConfig`, `SecurityConfig`, `RouteConfig`, `ToolPolicyConfig`) used everywhere else.
- `src/tool-policy.ts` — `ToolPolicy` class: evaluates glob-based allow/deny lists. Used in two ways: `findBlockedCall()` rejects `tools/call` requests before they reach the upstream; `filterToolsListPayload()` strips denied tools from `tools/list` JSON responses. SSE streams are never inspected.
- `src/upstream-dispatcher.ts` — creates the undici `Agent` used for all upstream requests. When `allowPrivateUpstreamsOnly: true`, wraps DNS resolution to reject non-private-network addresses (SSRF mitigation).
- `src/config-service.ts` — `ConfigService` wraps config loading with a `reload()` method for hot-reload without restarting the process. Holds the current `GatewayConfig` in memory; `reload()` is atomic (throws and leaves current config unchanged if the new file is invalid).
- `src/config-writer.ts` — `writeConfigAtomic(configPath, content)` validates YAML content, writes via temp file + fsync + atomic rename, keeps up to 5 timestamped `.bak` backups of the previous file.
- `src/state.ts` — `StateStore` wraps `node:sqlite` (`DatabaseSync`). `open()` creates the state directory (mode 0700), opens/creates `gateway.db` (mode 0600), runs SQLite PRAGMAs (WAL, foreign keys, synchronous=NORMAL), applies pending migrations in transactions, and runs an integrity check. `close()` closes the database. The `database` getter exposes the handle for admin and future OAuth routes. `MIGRATIONS` array is the source of truth for all schema versions; names must be stable across releases.
- `src/admin-auth.ts` — all authentication primitives: Argon2id password hashing (`@node-rs/argon2`), one-time bootstrap credential (SHA-256 hash stored, timing-safe comparison), session management (32-byte random token → SHA-256 hash in DB), CSRF tokens (24-byte random, session-bound), per-IP login rate limiting (DB-backed, survives restarts), and audit event logging.
- `src/admin-app.ts` — separate Fastify instance for the admin listener (default port 8789). Routes: `GET/POST /admin/setup` (first-run bootstrap), `GET/POST /admin/login`, `POST /admin/logout`, `GET /admin/dashboard`, `GET /admin/config`, `POST /admin/config/preview` (validates YAML via temp file), `POST /admin/config` (saves with session rotation). Every response gets security headers (DENY framing, nosniff, no-referrer, CSP, no-store). All state-changing routes require both session auth and CSRF validation. Config save rotates the session token and triggers `onConfigSaved` callback (used in `server.ts` for hot-reload).

**Transport endpoints per configured route:**

Each `path: /prefix` + `upstream: http://backend` entry in `routes[]` causes the gateway to register three endpoints:

| Endpoint           | Methods         | Upstream           | Transport                                       |
| ------------------ | --------------- | ------------------ | ----------------------------------------------- |
| `/prefix/mcp`      | GET POST DELETE | `backend/mcp`      | MCP streamable HTTP                             |
| `/prefix/sse`      | GET             | `backend/sse`      | Legacy HTTP+SSE — rewrites `endpoint` event URL |
| `/prefix/messages` | POST DELETE     | `backend/messages` | Legacy HTTP+SSE messages                        |

**SSE endpoint URL rewriting:** When an upstream SSE response contains an `event: endpoint` event (used by the legacy HTTP+SSE transport to tell clients where to POST messages), the gateway rewrites the URL in the `data:` field from the upstream's internal address to the gateway's own `/prefix/messages` URL. The public host is derived from the `Host` request header (which Cloudflare Tunnel forwards as the public hostname). After the endpoint event is processed, subsequent SSE chunks pass through as raw bytes.

**Request flow:**

```
Incoming request
  → Host header validation (allowedHosts)
  → Concurrent request limit check
  → Tool policy: findBlockedCall() → 403 if denied (tools/call only; not applied to GET /sse)
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

Key security defaults: `allowPrivateUpstreamsOnly: true` (blocks public-internet upstreams at DNS resolution time), `defaultDenyDangerousTools: true` (denies tools matching shell/exec/write/delete/restart/stop/start/reboot/shutdown/update/install).

## Security Constraints

- Do not commit real hostnames, IPs, tokens, credentials, or machine-specific paths — they belong in gitignored `gateway.yaml` and `.env`.
- `src/server.ts` is excluded from coverage thresholds intentionally — do not add it to `--test-coverage-include` flags.
- Coverage thresholds (90% lines, 75% branches, 90% functions) are applied to the aggregate of all `--test-coverage-include` files: `src/admin-app.ts`, `src/admin-auth.ts`, `src/app.ts`, `src/config.ts`, `src/config-service.ts`, `src/config-writer.ts`, `src/state.ts`, `src/tool-policy.ts`, and `src/upstream-dispatcher.ts`. Changes to any of these files must maintain the aggregate thresholds.
- Security-sensitive changes require a regression test.
- The `/health` endpoint intentionally exposes nothing beyond `{ status: "ok" }`. Do not add routes, version, or upstream details to it.
- The `/diagnostics` endpoint is disabled by default; it requires `GATEWAY_DIAGNOSTICS_TOKEN` ≥ 32 chars and Bearer auth. Token comparison uses `timingSafeEqual`.

## Admin App

The admin app runs as a completely separate Fastify instance on `admin.host:admin.port` (default `127.0.0.1:8789`). It is only started when `admin.enabled: true` in config. The public MCP listener (port 8788) never registers any `/admin/*` routes — they 404 by construction.

**First-run flow:** On first start with `admin.enabled: true`, the bootstrap credential (24 bytes base64url) is printed to stdout once. The operator visits `/admin/setup`, enters the credential and a password (≥12 chars), and the admin is ready. The bootstrap token is consumed (one-time only).

**Session/CSRF:** Login issues a session cookie (`mcp_admin_session`, httpOnly, sameSite=strict, path=/admin). Each session carries a CSRF token stored in the DB. State-changing routes require both a valid session AND the matching CSRF token in the request body. Session rotation happens on config save.

**Admin config settings (in `gateway.yaml`):** `admin.port` (must differ from 8788), `admin.host` (default 127.0.0.1), `admin.sessionTtlSeconds` (default 28800), `admin.maxLoginAttemptsPerHour` (default 10), `admin.loginLockoutSeconds` (default 900). Admin config changes require a gateway restart to take effect.

## Current Status

Phases 0 (security baseline), 1 (reloadable config, SQLite state store, atomic config writes), and 2 (local administration — separate admin listener, Argon2id auth, session/CSRF, rate limiting, config editor UI) are complete. Do not configure Cloudflare Tunnel for MCP routes until OAuth (Phases 3–5 in `ProjectSpec.md`) is implemented. See `docs/SECURE_DEPLOYMENT_CHECKLIST.md` for the full exposure-readiness checklist.
