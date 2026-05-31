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
4. Automated tests.
5. A production TypeScript build.

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

## Roadmap

### Phase 1: Minimal Gateway

- Complete the initial delivery described above.
- Validate against the Unraid Management Agent.
- Add container build verification in an environment with Docker.

### Phase 2: Backend Expansion

- Add local route configuration for Home Assistant, Hubitat, and Plex MCP
  servers as they become available.
- Add backend-specific compatibility tests where behavior differs.
- Add operational documentation for logging and troubleshooting.

### Phase 3: External Authentication

- Add ChatGPT-compatible OAuth before exposing sensitive backends to untrusted
  clients.
- Document token storage, redirect URLs, scopes, and Cloudflare interaction.
- Add authentication and authorization regression tests.

### Phase 4: Hardening

- Add request timeouts, body-size limits, and configurable upstream retry
  behavior where MCP semantics permit it.
- Add metrics and structured audit events for denied calls.
- Add container image scanning and release automation.
