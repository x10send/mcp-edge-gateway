# Installation Guide

## Prerequisites

- Unraid with Docker support
- A Cloudflare account with a tunnel pointed at your host

---

## 1. Add the container

In the Unraid UI, go to **Docker → Add Container** and fill in:

| Field | Value |
|---|---|
| Repository | `ghcr.io/x10send/mcp-edge-gateway:latest` |
| Port | `8788:8788` (public MCP) |
| Port | `8789:8789` (admin UI — LAN only, do not tunnel) |
| Path | `/mnt/user/appdata/mcp-edge-gateway` → `/config` |
| Path | `/mnt/user/appdata/mcp-edge-gateway/state` → `/config/state` |

Set the `/config` mount to **read/write** so the admin UI can save config changes.

## 2. Create gateway.yaml

Before starting, create `/mnt/user/appdata/mcp-edge-gateway/gateway.yaml`.
Copy from [`gateway.example.yaml`](../gateway.example.yaml) and set your tunnel
hostname and backend:

```yaml
oauth:
  enabled: true
  issuer: https://your-subdomain.example.com

security:
  publicOrigin: https://your-subdomain.example.com
  allowedHosts:
    - your-subdomain.example.com
  requireAuth: true

admin:
  enabled: true
  host: 0.0.0.0

routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
```

## 3. Start and bootstrap

Start the container, then check the logs for the one-time bootstrap credential:

```bash
docker logs mcp-edge-gateway | grep BOOTSTRAP
```

Visit `http://your-lan-ip:8789/admin/setup`, enter the credential, and set an
admin password (12+ characters).

## 4. Set the OAuth password

Log in at `http://your-lan-ip:8789/admin/login`, go to **OAuth User**, and set
a password. This is what you'll enter when Claude.ai prompts you to log in.

## 5. Connect Claude.ai or Claude Code

**Claude.ai:** Add a new MCP connector with your tunnel URL:
```
https://your-subdomain.example.com/unraid/mcp
```

**Claude Code:**
```bash
claude mcp add --transport http https://your-subdomain.example.com/unraid/mcp
```

Claude.ai will walk you through OAuth login using the password from step 4.

---

## Cloudflare Tunnel

Point the tunnel public hostname at `http://localhost:8788`. Don't route
port 8789 through the tunnel.

Disable caching for `/mcp`, `/sse`, `/messages`, and `/oauth` paths in
Cloudflare Cache Rules.

> **AI Crawl Control:** If you have "Block AI training bots" enabled in
> Cloudflare Security settings, Claude.ai will fail after OAuth — Anthropic's
> MCP broker is classified as a bot. Set it to **Allow**.

---

## Troubleshooting

**Gateway exits immediately:** Check `gateway.yaml` — route paths must be base
paths like `/unraid`, not `/unraid/mcp`.

**Claude.ai shows "Authorization failed" after login:** Check Cloudflare AI
Crawl Control (see above).

**Can't reach admin UI:** Make sure `admin.host: 0.0.0.0` is set in
`gateway.yaml`.

**Need to reset the admin password:**

```bash
sqlite3 /mnt/user/appdata/mcp-edge-gateway/state/gateway.db \
  "DELETE FROM admin_credentials;"
docker restart mcp-edge-gateway
```
