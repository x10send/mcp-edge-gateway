# MCP Edge Gateway

A small Dockerized Fastify gateway for routing MCP streamable HTTP traffic to
local MCP servers. It is intended to run on Unraid and sit behind a Cloudflare
Tunnel.

The initial route is:

```text
https://mcp.example.com/unraid/mcp -> http://unraid-agent.local:8043/mcp
```

## Features

- Route-based MCP proxying for `GET`, `POST`, and `DELETE`
- Streaming relay for MCP SSE responses
- Preservation of end-to-end headers, including `Mcp-Session-Id`
- Configurable case-insensitive glob allowlist and denylist
- Default denial of tool names containing `shell`, `exec`, `write`, `delete`,
  `restart`, `stop`, `start`, `reboot`, `shutdown`, `update`, or `install`
- JSON `tools/list` filtering and server-side blocking of denied `tools/call`
- Health endpoint at `/health`

OAuth is not included in this first release. Add it before exposing sensitive
backends to untrusted clients.

## Configuration

The container reads `/config/gateway.yaml`. Start with
[`gateway.example.yaml`](./gateway.example.yaml):

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

`allow` and `deny` entries support `*` globs and are case-insensitive. Deny
rules win over allow rules. To explicitly expose a dangerous tool, first set
`defaultDenyDangerousTools: false`, then define a narrow allowlist.

The gateway filters JSON `tools/list` responses. SSE responses are streamed
unchanged, but denied `tools/call` requests are always blocked before reaching
the upstream server.

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
printf 'GATEWAY_CONFIG_FILE=/mnt/user/appdata/mcp-edge-gateway/gateway.yaml\n' > .env
```

Build and start the container from this repository:

```bash
docker compose up -d --build
curl http://localhost:8788/health
```

The compose file publishes port `8788` and mounts the YAML config read-only.
The ignored `.env` file keeps the machine-specific mount path out of source
control. For local development, the default mount path is the ignored
`./gateway.yaml`.
After changing the YAML file, restart the container:

```bash
docker compose restart mcp-edge-gateway
```

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

## Cloudflare Tunnel

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
  - path: /unraid/mcp
    upstream: http://unraid-agent.local:8043/mcp
  - path: /homeassistant/mcp
    upstream: http://home-assistant.local:8123/mcp
```

## License

MIT
