# MCP Edge Gateway

A small Dockerized Fastify gateway for routing MCP streamable HTTP traffic to
local MCP servers. It is intended to run on Unraid and sit behind a Cloudflare
Tunnel.

Each configured backend exposes three endpoints automatically:

```text
GET/POST/DELETE /unraid/mcp      -> http://unraid-agent.local:8043/mcp  (streamable HTTP)
GET             /unraid/sse      -> http://unraid-agent.local:8043/sse  (legacy HTTP+SSE)
POST/DELETE     /unraid/messages -> http://unraid-agent.local:8043/messages
```

## Features

- Path-prefix routing: one `routes[]` entry registers `/mcp`, `/sse`, and `/messages` endpoints for a backend
- Streaming relay for MCP SSE responses; rewrites `endpoint` event URLs for the legacy HTTP+SSE transport
- Preservation of end-to-end headers, including `Mcp-Session-Id`
- Configurable case-insensitive glob allowlist and denylist
- Default denial of tool names containing `shell`, `exec`, `write`, `delete`,
  `restart`, `stop`, `start`, `reboot`, `shutdown`, `update`, or `install`
- JSON `tools/list` filtering and server-side blocking of denied `tools/call`
- Health endpoint at `/health`

The current `main` branch includes an embedded OAuth authorization server for
Phase 4 development and testing. External exposure remains blocked until Phase
5 protocol integration, deployment validation, and release review are complete.

> **Security warning:** `v0.1.0` is a LAN-only development baseline. Do not
> expose MCP routes through Cloudflare Tunnel until the OAuth and security
> phases in [`ProjectSpec.md`](./ProjectSpec.md) are complete.

The gateway includes ChatGPT-compatible OAuth and an optional configuration web
page on a separate LAN-only administration listener. The administration
listener must not be forwarded through Cloudflare Tunnel. See
[`ProjectSpec.md`](./ProjectSpec.md) for the planned security boundaries.
OAuth tokens and passwords are stored separately from `gateway.yaml`; public
examples never include deployment credentials.
Admin session cookies are secure by default. Put the LAN-only admin listener
behind HTTPS, or explicitly enable `admin.insecureAllowHttpCookies` only for an
isolated direct-HTTP LAN setup.

## Configuration

The container reads `/config/gateway.yaml`. Start with
[`gateway.example.yaml`](./gateway.example.yaml):

```yaml
server:
  host: 0.0.0.0
  port: 8788
  logLevel: info

diagnostics:
  enabled: false
  tokenEnv: GATEWAY_DIAGNOSTICS_TOKEN

oauth:
  enabled: false
  issuer: https://localhost
  insecureAllowHttpIssuer: false

security:
  publicOrigin: http://localhost:8788
  insecureAllowHttpPublicOrigin: true
  allowedHosts:
    - localhost
    - 127.0.0.1
  trustedProxies: []
  allowPrivateUpstreamsOnly: true
  requireAuth: false
  insecureAllowUnauthenticatedMcp: true

tools:
  defaultDenyDangerousTools: true
  allow: []
  deny: []

routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
```

`allow` and `deny` entries support `*` globs and are case-insensitive. Deny
rules win over allow rules. To explicitly expose a dangerous tool, first set
`defaultDenyDangerousTools: false`, then define a narrow allowlist.

The gateway filters JSON `tools/list` responses. SSE responses are streamed
unchanged, but denied `tools/call` requests are always blocked before reaching
the upstream server.

The default security configuration accepts local host headers, trusts no
reverse proxies, limits request sizes and stream lifetimes, and permits only
private-network MCP upstreams. Add deployment-specific hostnames explicitly.
The example opts into unauthenticated MCP only for LAN development. Before any
external exposure, set an explicit HTTPS `publicOrigin`, set `requireAuth:
true`, and remove `insecureAllowHttpPublicOrigin` and
`insecureAllowUnauthenticatedMcp`.
Optional `/diagnostics` output is disabled unless configured with a local
`GATEWAY_DIAGNOSTICS_TOKEN` containing at least 32 characters.

When OAuth is enabled, the public listener serves authorization-server metadata,
PKCE authorization-code login and consent, token refresh, revocation, dynamic
client registration, and Client ID Metadata Document discovery. Configure the
separate OAuth resource-owner password from the LAN-only admin page before
connecting a remote client.

## Local Development

```bash
cp gateway.example.yaml gateway.yaml
GATEWAY_CONFIG=./gateway.yaml npm install
GATEWAY_CONFIG=./gateway.yaml npm run dev
```

Run the full quality suite before submitting changes:

```bash
npm run check
```

Run tests with the enforced coverage report directly:

```bash
npm run test:coverage
```

See [`ProjectSpec.md`](./ProjectSpec.md) for the architecture and roadmap, and
[`CONTRIBUTING.md`](./CONTRIBUTING.md) for testing and public-repository rules.

Check the gateway:

```bash
curl http://localhost:8788/health
curl http://localhost:8788/unraid/mcp
```

The second request should transparently relay the Unraid agent response. Since
the Unraid agent requires session state, a bare `GET` may return:

```text
Bad Request: GET requires an Mcp-Session-Id header
```

That confirms the request reached the upstream MCP endpoint.

## Deploy on Unraid

Create the config directory and place the YAML file there:

```bash
mkdir -p /mnt/user/appdata/mcp-edge-gateway
cp gateway.example.yaml /mnt/user/appdata/mcp-edge-gateway/gateway.yaml
```

Create `.env` with the host-side paths (gitignored):

```bash
printf 'GATEWAY_CONFIG_DIR=/mnt/user/appdata/mcp-edge-gateway\nGATEWAY_STATE_DIR=/mnt/user/appdata/mcp-edge-gateway/state\n' > .env
```

Pull and start the published image:

```bash
docker compose up -d
curl http://localhost:8788/health
```

To build locally from source instead, set `GATEWAY_IMAGE=` in `.env` (empty
overrides the default image reference so Compose falls back to `build: .`):

```bash
printf 'GATEWAY_IMAGE=\n' >> .env
docker compose up -d --build
```

After changing the YAML file, restart the container:

```bash
docker compose restart mcp-edge-gateway
```

When the administration listener is enabled:

1. Set `admin.host: 0.0.0.0` in `gateway.yaml` — Docker's port forwarding
   cannot reach a container service bound only to `127.0.0.1`.
2. Mount `/config` read-write so atomic YAML replacement and backups work.
3. Set `GATEWAY_ADMIN_BIND_ADDRESS` to your Unraid host's LAN IP so the admin
   UI is reachable from a browser on your LAN:

```bash
printf 'GATEWAY_ADMIN_BIND_ADDRESS=192.168.1.x\n' >> .env   # replace with your Unraid LAN IP
docker compose -f docker-compose.yml -f docker-compose.admin.yml up -d
```

Keep the admin bind address LAN-only. Do not forward port `8789` through
Cloudflare Tunnel.

## Container Releases

Version tags publish container images to GitHub Container Registry:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow publishes:

```text
ghcr.io/x10send/mcp-edge-gateway:0.1.0
ghcr.io/x10send/mcp-edge-gateway:0.1
ghcr.io/x10send/mcp-edge-gateway:0
ghcr.io/x10send/mcp-edge-gateway:latest
```

Pull the latest release on Unraid with:

```bash
docker pull ghcr.io/x10send/mcp-edge-gateway:latest
```

For reviewed deployments, pin the immutable digest emitted by the release
workflow instead of relying only on a mutable tag:

```bash
docker pull ghcr.io/x10send/mcp-edge-gateway@sha256:<release-digest>
gh attestation verify \
  oci://ghcr.io/x10send/mcp-edge-gateway@sha256:<release-digest> \
  --repo x10send/mcp-edge-gateway
```

Release images include an SBOM and GitHub build-provenance attestation.

The checked-in CodeQL workflow is manual while the repository remains private.
Enable its push, pull-request, and scheduled triggers when the repository is
public or GitHub Advanced Security is available.

Required branch-protection checks are also pending the public transition or a
GitHub plan that supports protection rules for private repositories.

## Cloudflare Tunnel

The following is a future deployment step. Do not enable it for `v0.1.0`.
Complete [`docs/SECURE_DEPLOYMENT_CHECKLIST.md`](./docs/SECURE_DEPLOYMENT_CHECKLIST.md)
before external exposure.

In the Cloudflare Zero Trust dashboard, add a public hostname to the tunnel:

```text
Hostname: mcp.example.com
Service:  HTTP
URL:      http://unraid-host.local:8788
```

Then verify:

```bash
curl https://mcp.example.com/health
curl https://mcp.example.com/unraid/mcp
```

Cloudflare should pass MCP request and response headers through unchanged. Do
not configure caching for MCP routes.

## Add Another Backend

Add another item under `routes`, then restart the gateway:

```yaml
routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
  - path: /homeassistant
    upstream: http://home-assistant.local:8123
```

## License

MIT
