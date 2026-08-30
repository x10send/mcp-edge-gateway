# 2026 Q3 Security Update

Security findings from audit conducted 2026-08-27 against HEAD `4e17785`. No critical issues found. Fixes organized by risk and implementation effort.

---

## Phase 1 — Dependency Upgrades (High priority, low effort)

**Addresses:** H-1, H-2, L-3

- [x] Upgrade `undici` 8.3.0 → 8.10.0 (fixes 12 HIGH CVEs: HTTP response queue poisoning, header injection, cross-user info disclosure, CRLF injection, cookie attribute injection, etc.)
- [x] Upgrade `fastify` 5.8.5 → 5.12.1 (force `find-my-way` → 9.9.0 and `fast-uri` → 3.1.6 via `overrides`, fixing HTTP/2 DDoS and host-confusion CVEs)
- [x] Upgrade `@fastify/cookie` 11.0.2 → 11.1.2
- [x] Upgrade `@node-rs/argon2` 2.0.2 → 2.1.0
- [x] Upgrade remaining dev deps (eslint, typescript-eslint, prettier, tsx, @types/node) to `wanted` versions
- [x] Force `brace-expansion` → 5.0.9 and `esbuild` → 0.28.2 via `overrides` (dev-only CVEs)
- [x] Verified `npm audit` clean (0 vulnerabilities)
- [x] `npm run check` passes (281/281 tests)

---

## Phase 2 — SSRF Hardening (High priority, low effort)

**Addresses:** H-3

`isPrivateNetworkAddress` in `src/config.ts` does not cover IPv4 loopback (`127.x.x.x`), IPv4 link-local (`169.254.x.x`), IPv6 loopback (`::1`), or IPv6 link-local (`fe80::`). The runtime `privateLookup` in `src/upstream-dispatcher.ts` incidentally rejects these via the RFC-1918 check, but the semantic gap is a future bug risk and could allow SSRF if a hostname resolves to both a private and a loopback address.

- [x] Added `isSpecialUseNetworkAddress` in `src/config.ts` covering `127.x.x.x`, `169.254.x.x`, `::1`, `fe80::` (with zone-ID stripping)
- [x] Config validator now explicitly rejects loopback/link-local literal IPs regardless of `allowPrivateUpstreamsOnly` (H-3 fix with defense-in-depth)
- [x] `selectPrivateLookupAddress` in `src/upstream-dispatcher.ts` now explicitly filters out special-use addresses in addition to non-private ones (prevents DNS-rebinding SSRF)
- [x] `isPrivateNetworkAddress` retains RFC-1918/ULA-only semantics with clarifying comment; separation of concerns is explicit
- [x] Tests in `test/upstream-dispatcher.test.ts` cover all new ranges, DNS skip-loopback-select-private scenario, and the two-function contract
- [x] `npm run check` passes (281/281 tests)

---

## Phase 3 — Timing-Safe CSRF Comparisons (Medium priority, low effort)

**Addresses:** M-4, M-5

Two CSRF token comparisons use direct string equality (`===`/`!==`) rather than `timingSafeEqual`. All other secret comparisons in the codebase (session tokens, diagnostic tokens, bootstrap tokens) use timing-safe comparison.

- [x] `src/admin-app.ts` `requireCsrf`: replaced `submitted !== session.csrfToken` with `timingSafeEqual` (with length pre-check to avoid crash on mismatched buffer lengths)
- [x] `src/oauth-authorization-server.ts` `validCsrf`: replaced `submitted === tx.csrfToken` with `timingSafeEqual` (same pattern)
- [x] Tests added: same-length wrong CSRF, empty CSRF, correct CSRF — for both admin and OAuth login/consent flows
- [x] `npm run check` passes (281/281 tests)

---

## Phase 4 — OAuth Input Validation & Rate Limiting (Medium priority, medium effort)

**Addresses:** M-1, M-3

- [x] Add migration `006_oauth_token_attempts` to `src/state.ts` (table with `ip_address`, `endpoint`, `created_at` columns; index on `ip_address, endpoint, created_at`)
- [x] Add IP-based rate limiting to `POST /oauth/token` (≤`tokenRateLimitPerMinute` req/min/IP, default 20) — reuses sliding-window pattern from registration rate limiting
- [x] Add IP-based rate limiting to `POST /oauth/revoke` (≤`revokeRateLimitPerMinute` req/min/IP, default 60)
- [x] Validate `state` parameter in OAuth authorization requests: max 512 chars, URL-safe characters only (`/^[\w\-._~%+/=]*$/`)
- [x] Tests added: token rate limit 429, revoke rate limit 429, state too long 400, state invalid chars 400 — all using isolated configs to avoid interfering with other tests
- [x] `npm run check` passes (287/287 tests)

---

## Phase 5 — Admin Hardening (Medium priority, medium effort)

**Addresses:** M-2, M-6, L-2 (L-1 accepted as-is)

- [x] Propagate `security.trustedProxies` to the admin Fastify instance (`trustProxy` option) so IP-based login rate limiting uses the real client IP behind a reverse proxy — matches the pattern already used in the public listener
- [x] Test added: login from forwarded IP X is rate-limited independently from forwarded IP Y when trustedProxies is configured
- [x] Harden `htmlError()` in `src/admin-app.ts`: renamed parameter from `message` to `safeHtml`; added JSDoc warning that callers must pre-escape any interpolated values via `escapeHtml()` before passing
- [x] Documented session IP binding non-implementation in CLAUDE.md (L-2): by design for single-operator LAN use, not a security gap in the threat model
- [x] `npm run check` passes (288/288 tests)

---

## Status

| Phase                                      | Status   | Commit |
| ------------------------------------------ | -------- | ------ |
| 1 — Dependency upgrades                    | complete | —      |
| 2 — SSRF hardening                         | complete | —      |
| 3 — Timing-safe CSRF                       | complete | —      |
| 4 — OAuth rate limiting & state validation | complete | —      |
| 5 — Admin hardening                        | complete | —      |
