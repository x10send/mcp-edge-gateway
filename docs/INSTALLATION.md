# Installation Guide

## Prerequisites

- Unraid with Docker support (or any Docker host)
- A Cloudflare account with a tunnel pointed at your host

---

## 1. Create your config

```bash
mkdir -p /mnt/user/appdata/mcp-edge-gateway
```

Copy `gateway.example.yaml` into that directory as `gateway.yaml` and set your
tunnel hostname and routes:

```yaml
server:
  host: 0.0.0.0
  port: 8788

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
  port: 8789

routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
```

## 2. Start the container

Create `.env`:

```bash
printf 'GATEWAY_CONFIG_DIR=/mnt/user/appdata/mcp-edge-gateway\nGATEWAY_STATE_DIR=/mnt/user/appdata/mcp-edge-gateway/state\nGATEWAY_ADMIN_BIND_ADDRESS=192.168.1.x\n' > .env
```

Replace `192.168.1.x` with your Unraid host's LAN IP, then start:

```bash
docker compose -f docker-compose.yml -f docker-compose.admin.yml up -d
```

## 3. Set up the admin account

Check the container logs for the one-time bootstrap credential:

```bash
docker logs mcp-edge-gateway | grep BOOTSTRAP
```

Visit `http://your-lan-ip:8789/admin/setup`, enter the credential, and set an
admin password (12+ characters).

## 4. Set the OAuth password

Log in at `http://your-lan-ip:8789/admin/login`, go to **OAuth User**, and set
a password. This is what you'll enter when Claude.ai asks you to log in.

## 5. Connect Claude.ai or Claude Code

In Claude.ai, add a new MCP connector with your tunnel URL:

```
https://your-subdomain.example.com/unraid/mcp
```

Claude.ai will redirect you through OAuth login. Use the password you set in
step 4.

For Claude Code:

```bash
claude mcp add --transport http https://your-subdomain.example.com/unraid/mcp
```

---

## Cloudflare Tunnel

Point the tunnel public hostname at `http://localhost:8788` (or
`http://unraid-ip:8788`). Don't route port 8789 through the tunnel.

Disable caching for `/mcp`, `/sse`, `/messages`, and `/oauth` paths in
Cloudflare Cache Rules.

> **AI Crawl Control:** If you have "Block AI training bots" enabled in
> Cloudflare Security settings, Claude.ai will fail to connect after OAuth —
> Anthropic's MCP broker is classified as a bot. Set it to **Allow**.

---

## Backup

Back up `/mnt/user/appdata/mcp-edge-gateway` — it contains your config and the
SQLite database with tokens and credentials. Treat it as sensitive.

---

## Troubleshooting

**Gateway exits immediately:** Check `gateway.yaml` — route paths must be base
paths like `/unraid`, not `/unraid/mcp`.

**Claude.ai shows "Authorization failed" after login:** Check Cloudflare AI
Crawl Control (see above).

**Can't reach admin UI:** Make sure `admin.host: 0.0.0.0` is set and
`GATEWAY_ADMIN_BIND_ADDRESS` is your host's LAN IP, not `127.0.0.1`.

**Need to reset the admin password:** Delete the credentials row and restart:

```bash
sqlite3 /mnt/user/appdata/mcp-edge-gateway/state/gateway.db \
  "DELETE FROM admin_credentials;"
docker restart mcp-edge-gateway
```
