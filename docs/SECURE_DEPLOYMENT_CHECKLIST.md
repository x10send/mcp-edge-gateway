# Secure Deployment Checklist

## Development Baseline

The `v0.1.0` image is for LAN-only development. Do not expose MCP routes
through Cloudflare Tunnel until the OAuth and security gates in
[`ProjectSpec.md`](../ProjectSpec.md) are complete.

## Before External Exposure

- [ ] Use a release explicitly documented as safe for external exposure.
- [ ] Verify CI, container scanning, SBOM generation, and provenance
      attestation for the selected image digest.
- [ ] Deploy by immutable image digest rather than only a mutable tag.
- [ ] Enable OAuth and verify protected-resource and authorization-server
      metadata.
- [ ] Verify unauthenticated MCP requests fail with `401`.
- [ ] Verify insufficient scopes fail with `403`.
- [ ] Keep the administration listener disabled or LAN-only.
- [ ] Confirm Cloudflare Tunnel forwards only the public listener.
- [ ] Disable caching for MCP and OAuth paths.
- [ ] Configure trusted proxy addresses explicitly.
- [ ] Review route upstream allowlists and tool allowlists.
- [ ] Keep dangerous tool defaults enabled.
- [ ] Run allowed-tool and blocked-tool end-to-end checks.
- [ ] Back up `/config` securely and test restore procedures.
- [ ] Test credential rotation and token revocation.
- [ ] Record accepted residual risks for the release.

## Incident Response

If a token, credential, backup, or host may be compromised:

1. Remove external tunnel access.
2. Revoke active OAuth tokens and client registrations.
3. Rotate administrator and OAuth-user credentials.
4. Replace bootstrap credentials if setup was incomplete.
5. Inspect audit logs and local MCP backend logs.
6. Restore only from a trusted backup.
7. Revoke credentials created after the restored backup.
8. Re-enable external access only after the deployment checklist passes.
