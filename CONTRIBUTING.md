# Contributing

## Development Setup

```bash
npm ci
cp gateway.example.yaml gateway.yaml
npm run check
```

Use `GATEWAY_CONFIG=./gateway.yaml npm run dev` to start a local gateway.

## Required Checks

Run `npm run check` before opening a pull request. It verifies formatting,
linting, type safety, tests, and the production build. CI runs the same command
for every pull request and push to `main`. CI also builds the Docker image.

`npm run test:coverage` enforces at least 90% line coverage, 75% branch
coverage, and 90% function coverage across the testable application modules.
`src/server.ts` is a thin process bootstrap and is excluded from the coverage
gate.

Changes to proxy behavior must add or update tests. At minimum, preserve
coverage for health reporting, MCP session headers, query strings, SSE relay,
tool discovery filtering, and blocked tool calls. Security-sensitive changes
must include a regression test.

## Public Repository Rules

Do not commit real hostnames, IP addresses, tunnel IDs, tokens, credentials, or
machine-specific paths. Put local backend addresses in `gateway.yaml`, which is
ignored by git. Put Docker Compose mount overrides in `.env`, which is also
ignored. Keep public examples generic.

## Releases

Push a semantic version tag such as `v0.1.0` only after CI passes on `main`.
GitHub Actions publishes versioned and `latest` images to
`ghcr.io/x10send/mcp-edge-gateway`.
