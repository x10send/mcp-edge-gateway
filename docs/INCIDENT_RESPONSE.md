# Incident Response Runbook

This runbook covers containment and recovery steps for the most likely
incidents on a self-hosted MCP Edge Gateway deployment.

---

## Token Theft

**Indicators:** unexpected MCP requests in logs, unfamiliar client IDs in the
token list, active tokens you did not issue.

### Containment

1. Navigate to the admin UI **Tokens** page and revoke all active tokens.
   Revoking an access token also revokes its refresh token family.
2. If you cannot reach the admin UI, revoke directly in the database:

   ```bash
   sqlite3 /mnt/user/appdata/mcp-edge-gateway/config/state/gateway.db \
     "UPDATE oauth_tokens SET revoked_at = unixepoch() WHERE revoked_at IS NULL;"
   sqlite3 /mnt/user/appdata/mcp-edge-gateway/config/state/gateway.db \
     "UPDATE oauth_refresh_tokens SET revoked_at = unixepoch() WHERE revoked_at IS NULL;"
   ```

3. Remove external tunnel access immediately if the stolen token is still
   valid (access tokens last `accessTokenTtlSeconds`, default 15 minutes).

### Recovery

1. Rotate the OAuth resource-owner password via **OAuth User** in the admin UI.
2. Reissue tokens to known clients with narrower scope and shorter expiry.
3. Review audit events in `state/gateway.db`:

   ```bash
   sqlite3 /mnt/user/appdata/mcp-edge-gateway/config/state/gateway.db \
     "SELECT * FROM audit_events ORDER BY created_at DESC LIMIT 50;"
   ```

4. If the theft resulted from a compromised client system, remove that client's
   registered `client_id` from `oauth_clients` and refuse future registrations
   from its redirect URI.

---

## Host Compromise

**Indicators:** unexpected processes on the Unraid host, unfamiliar SSH keys,
files modified in `/config`, container logs from unexpected IPs.

A compromised host means all secrets on the host are potentially exposed: the
admin password hash, the OAuth user password hash, and any token hashes in
`state/gateway.db`. Although hashes are not plaintext secrets, Argon2id
parameters are known and an attacker with the hash and time can attempt
offline cracking.

### Containment

1. Immediately remove Cloudflare Tunnel access by disabling or deleting the
   tunnel in the Cloudflare dashboard.
2. Power off or isolate the Unraid host from the network.

### Recovery

1. Restore Unraid from a known-good backup taken before the compromise window.
2. Do not restore `gateway.yaml` or `state/gateway.db` from backups stored on
   the compromised host — treat them as contaminated.
3. Rebuild `/config` from scratch:
   - Create a new `gateway.yaml` from the example template.
   - Delete `state/gateway.db` so migrations run fresh on next start.
4. Start the gateway to trigger bootstrap and set a new administration password.
5. Set a new OAuth resource-owner password via the admin UI.
6. Revoke any existing OAuth client registrations by clearing `oauth_clients`
   (they will re-register on next connection).
7. Issue new Bearer tokens to legitimate clients.
8. Re-enable the Cloudflare Tunnel only after completing the full deployment
   checklist in `SECURE_DEPLOYMENT_CHECKLIST.md`.
9. Record the incident scope, timeline, and recovery actions.

---

## Stale Restore (Replay Attack)

**Situation:** You restored `state/gateway.db` from a backup, but tokens,
sessions, or refresh tokens issued after the backup point are no longer in the
database. Those credentials still exist externally (in clients or logs) and
could be replayed.

### Mitigation

1. After any restore, immediately revoke all active tokens:

   ```bash
   sqlite3 /config/state/gateway.db \
     "UPDATE oauth_tokens SET revoked_at = unixepoch() WHERE revoked_at IS NULL;"
   sqlite3 /config/state/gateway.db \
     "UPDATE oauth_refresh_tokens SET revoked_at = unixepoch() WHERE revoked_at IS NULL;"
   sqlite3 /config/state/gateway.db \
     "DELETE FROM admin_sessions;"
   ```

2. Rotate the admin password and OAuth user password.
3. Notify legitimate clients to re-authenticate. They will be prompted to log
   in again when their access token is rejected with 401.
4. Issue new tokens to clients who require them.

There is no way to revoke a session that was issued after the backup point and
before the revocation step — the window is bounded by the time between the
backup and the revocation. If that window included sensitive operations, treat
the incident as a potential token theft above.

---

## Malicious Upstream Discovery

**Situation:** An upstream MCP server you added to `routes[]` is behaving
maliciously: returning crafted `tools/list` payloads, attempting prompt
injection, or attempting SSRF through Client ID Metadata Document URLs.

### Containment

1. Remove the malicious route from `gateway.yaml` via the admin config editor.
   The route is immediately inaccessible after the config save (note: a gateway
   restart is required to stop serving the old route).
2. Restart the gateway container to apply the config change:

   ```bash
   docker restart mcp-edge-gateway
   ```

3. Revoke any tokens scoped to that route from the **Tokens** admin page.

### Mitigation

Tool policies (`defaultDenyDangerousTools`, per-route allow/deny lists) protect
against unauthorized tool calls. However, they do not prevent an upstream from
returning malicious content in `tools/list` descriptions or tool call responses.
Prompt injection through those fields is a residual risk documented in the
release notes.

---

## Administration Credential Compromise

**Indicators:** unexpected logins in the audit log, admin password stopped
working (attacker changed it), unfamiliar sessions active.

### Containment

1. If you can still log in, change the administration password immediately.
   All other sessions are invalidated on password change.
2. If you cannot log in (attacker changed the password), delete the
   `admin_credentials` row to re-trigger bootstrap:

   ```bash
   sqlite3 /config/state/gateway.db \
     "DELETE FROM admin_credentials;"
   docker restart mcp-edge-gateway
   ```

   The new bootstrap credential is printed to container logs. Set a new
   password immediately.

3. Review the audit log for changes made during the compromise window.
4. Rotate all OAuth tokens issued during the compromise window.

---

## Bootstrap Credential Exposure

**Situation:** The one-time bootstrap credential was logged, transmitted
insecurely, or otherwise exposed before setup was completed.

The bootstrap credential is stored as a SHA-256 hash. If it was seen by an
attacker before you consumed it, they could have set up the admin account
themselves.

### Response

1. Check whether `/admin/setup` has been completed — if the admin credentials
   table has a row, setup was completed. Verify it was you who completed it.
2. If you cannot verify, treat it as a compromised admin account (see above).
3. If setup has not been completed and the credential is compromised:

   ```bash
   sqlite3 /config/state/gateway.db \
     "DELETE FROM bootstrap_tokens;"
   docker restart mcp-edge-gateway
   ```

   A new credential will be issued on restart.

---

## General Escalation Contacts

- Gateway issues: <https://github.com/x10send/mcp-edge-gateway/issues>
- Cloudflare Tunnel status: <https://www.cloudflarestatus.com>
- Unraid community: <https://forums.unraid.net>
