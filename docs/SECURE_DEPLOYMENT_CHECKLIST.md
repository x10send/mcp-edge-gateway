# Secure Deployment Checklist

Complete all items before exposing MCP routes through Cloudflare Tunnel or any
other public ingress.

## Before External Exposure

- [ ] Deploy by immutable image digest rather than only a mutable tag.
- [ ] Verify CI, container scanning, SBOM generation, and provenance
      attestation for the selected image digest.
- [ ] Enable OAuth (`oauth.enabled: true`) and verify protected-resource and
      authorization-server metadata endpoints return correct JSON.
- [ ] Set the separate OAuth-user password and test login and consent flow.
- [ ] Set `security.requireAuth: true` and verify unauthenticated MCP requests
      fail with `401`.
- [ ] Verify insufficient scopes fail with `403`.
- [ ] Remove `insecureAllowHttpPublicOrigin` and
      `insecureAllowUnauthenticatedMcp` from `gateway.yaml`.
- [ ] Keep the administration listener disabled or bound to a LAN-only address.
- [ ] Confirm Cloudflare Tunnel forwards only the public listener (port 8788).
      Do not route port 8789 through the tunnel.
- [ ] Disable Cloudflare AI Crawl Control "Block AI training bots" for the
      tunnel hostname, or Anthropic's MCP broker will be blocked after OAuth.
- [ ] Disable caching for MCP, SSE, messages, and OAuth paths in Cloudflare
      Cache Rules.
- [ ] Configure `security.trustedProxies` to match your tunnel's IP range.
- [ ] Review route upstream URLs and tool allowlists for every configured
      backend.
- [ ] Keep `defaultDenyDangerousTools: true` unless there is a narrow,
      reviewed reason to disable it.
- [ ] Run an allowed-tool and a blocked-tool end-to-end check through the
      tunnel.
- [ ] Back up `/config` securely and verify restore works.
- [ ] Test credential rotation and token revocation.

## Incident Response

If a token, credential, backup, or host may be compromised:

1. Remove external tunnel access immediately.
2. Revoke active OAuth tokens and client registrations.
3. Rotate administrator and OAuth-user credentials.
4. Inspect audit logs and local MCP backend logs.
5. Restore only from a trusted backup.
6. Revoke any credentials issued after the restored backup point.
7. Re-enable external access only after the checklist passes again.

See [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) for the full runbook.
