# Installation Guide

This guide covers deploying MCP Edge Gateway on Unraid, configuring OAuth for
external exposure, managing backups, and rotating credentials.

## Prerequisites

- Unraid 6.12 or later with Community Applications and Docker support
- A Cloudflare account with Tunnel access (for external exposure)
- The image digest or tag you intend to deploy (see release notes for the
  validated prerelease digest)

---

## Initial Deployment

### 1. Create the config volume

The gateway stores all persistent state under `/config` inside the container.
Map this to a directory on your array or cache drive with restrictive
permissions.

On the Unraid host:

```bash
mkdir -p /mnt/user/appdata/mcp-edge-gateway/config
chmod 700 /mnt/user/appdata/mcp-edge-gateway/config
```

### 2. Create gateway.yaml

Copy `gateway.example.yaml` from the repository into your config directory and
edit it. Set at minimum:

```yaml
security:
  publicOrigin: https://your-subdomain.example.com # your Cloudflare Tunnel hostname
  allowedHosts:
    - your-subdomain.example.com

oauth:
  enabled: true
  issuer: https://your-subdomain.example.com

routes:
  - path: /unraid
    upstream: http://unraid-agent.local:8043
```

Remove both `insecureAllowHttpPublicOrigin: true` and
`insecureAllowUnauthenticatedMcp: true` before external exposure. Both flags
must be absent or `false` in production.

### 3. Start the container

Using Docker Compose (see `docker-compose.yml` in the repository):

```bash
GATEWAY_CONFIG=/config/gateway.yaml \
GATEWAY_STATE_DIR=/config/state \
docker compose up -d
```

Or via Unraid's template system: map host path
`/mnt/user/appdata/mcp-edge-gateway/config` to container path `/config`.

The public listener binds on port **8788**. The admin listener (when enabled)
binds on port **8789** and must never be forwarded through Cloudflare Tunnel.

### 4. First-run bootstrap

If `admin.enabled: true` in your config, a one-time bootstrap credential is
printed to container logs on first start:

```
BOOTSTRAP CREDENTIAL: <base64url string>
```

Visit `http://your-lan-ip:8789/admin/setup`, enter the credential, and set
an administration password (minimum 12 characters). The credential is consumed
immediately and cannot be reused.

### 5. Set the OAuth resource-owner password

Log in to the admin UI at `http://your-lan-ip:8789/admin/login`, navigate to
**OAuth User**, and set a separate password for OAuth logins. This password is
distinct from the administration password and is used only when a client
performs the OAuth authorization code flow.

### 6. Enable OAuth and verify

Set `oauth.enabled: true` and `security.requireAuth: true` in `gateway.yaml`,
then restart the container. Verify:

```bash
# Protected-resource metadata (should include authorization_servers)
curl https://your-subdomain.example.com/.well-known/oauth-protected-resource/unraid/mcp

# Authorization-server metadata
curl https://your-subdomain.example.com/.well-known/oauth-authorization-server

# Unauthenticated MCP request must return 401 with WWW-Authenticate
curl -i https://your-subdomain.example.com/unraid/mcp
```

---

## Cloudflare Tunnel Setup

Cloudflare Tunnel forwards HTTPS traffic to the container's public port 8788.
The administration port 8789 must **never** be routed through the tunnel.

1. In the Cloudflare Zero Trust dashboard, create a tunnel and point the
   public hostname to `http://localhost:8788` (or `http://unraid-ip:8788`
   if the tunnel runs on a different host).
2. Set `security.trustedProxies: ["100.64.0.0/10"]` in `gateway.yaml` so the
   gateway trusts the Cloudflare WARP IP range for `X-Forwarded-For`.
3. Add your Cloudflare Tunnel hostname to `security.allowedHosts`.
4. Disable caching for `/mcp`, `/sse`, `/messages`, and `/oauth` paths in your
   Cloudflare Cache Rules.

---

## Backup and Restore

### What to back up

Everything under `/config`:

- `gateway.yaml` — gateway configuration
- `gateway.yaml.bak.*` — timestamped configuration backups
- `state/gateway.db` — SQLite database (tokens, sessions, OAuth clients)

### Backup procedure

```bash
# Quiesce writes by pausing the container (optional; SQLite WAL handles concurrent access)
docker pause mcp-edge-gateway

# Archive the config directory
tar -czf gateway-backup-$(date +%Y%m%d%H%M%S).tar.gz \
  /mnt/user/appdata/mcp-edge-gateway/config

docker unpause mcp-edge-gateway
```

Store the archive offline or in a location not accessible from the Unraid host.
Treat backups as sensitive: they contain the hashed admin password, hashed
OAuth user password, and active token hashes.

### Restore procedure

1. Stop the container.
2. Replace `/mnt/user/appdata/mcp-edge-gateway/config` with the archive
   contents.
3. Verify file permissions: `chmod 700 config/ && chmod 600 config/gateway.yaml
config/state/gateway.db`.
4. Start the container.
5. Revoke any tokens issued after the restore point (see below) — they are
   present in the live database but not in the restored backup.

---

## Credential Rotation

### Administration password

Log in to the admin UI, navigate to **Dashboard**, and use the password change
form. The session is rotated on save. All other active sessions are invalidated
immediately.

### OAuth resource-owner password

Navigate to **OAuth User** in the admin UI and set a new password. Existing
issued access tokens remain valid until expiry. To invalidate them immediately,
revoke them from the **Tokens** page.

### Bearer tokens

Navigate to **Tokens** in the admin UI. Revoke individual tokens or issue new
ones with updated scope or expiry. Tokens are shown in plaintext only at
issuance and cannot be recovered afterward.

### Bootstrap credential

The bootstrap credential is a one-time secret consumed during initial setup. It
cannot be regenerated without resetting the admin account. To re-trigger
bootstrap, delete the `admin_credentials` row in `state/gateway.db`:

```bash
sqlite3 /mnt/user/appdata/mcp-edge-gateway/config/state/gateway.db \
  "DELETE FROM admin_credentials;"
```

Then restart the container. The next start prints a new bootstrap credential.

---

## Deployment Checklist

See [`SECURE_DEPLOYMENT_CHECKLIST.md`](SECURE_DEPLOYMENT_CHECKLIST.md) for the
complete pre-exposure checklist.
