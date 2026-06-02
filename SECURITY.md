# Security Policy

## Reporting a Vulnerability

Do not open a public issue for a suspected vulnerability. Report it privately
through GitHub Security Advisories for this repository. Include the affected
version, reproduction steps, impact, and any proposed mitigation.

## Deployment Guidance

This gateway can reach private MCP backends. Before exposing it to untrusted
clients:

- Complete [`docs/SECURE_DEPLOYMENT_CHECKLIST.md`](./docs/SECURE_DEPLOYMENT_CHECKLIST.md).
- Add and validate OAuth authentication.
- Keep backend addresses, tunnel details, tokens, and credentials out of git.
- Review tool allowlists and denylists for every configured backend.
- Keep `defaultDenyDangerousTools: true` unless a deployment has a narrow,
  reviewed reason to disable it.
- Disable caching for MCP routes at the reverse proxy.

Local deployment values belong in ignored `gateway.yaml` and `.env` files.

No release should be described as bulletproof. Document residual risks,
especially bearer-token theft, prompt injection, compromised local MCP
backends, compromised Unraid hosts, and unauthorized access to `/config`.
