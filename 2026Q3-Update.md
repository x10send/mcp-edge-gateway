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

- [ ] Add IP-based rate limiting to `POST /oauth/token` (≤20 req/min/IP) reusing the existing DB-backed rate-limiter from `admin-auth.ts`
- [ ] Add IP-based rate limiting to `POST /oauth/revoke` (≤60 req/min/IP)
- [ ] Validate `state` parameter in OAuth authorization requests: max 512 chars, URL-safe characters only (`/^[\w\-._~%+/=]*$/`)
- [ ] Add tests for rate limiting and state validation
- [ ] Verify `npm run check` passes

---

## Phase 5 — Admin Hardening (Medium priority, medium effort)

**Addresses:** M-2, M-6, L-2 (L-1 accepted as-is)

- [ ] Propagate `security.trustedProxies` (or a separate `admin.trustedProxies` config field) to the admin Fastify instance so IP-based login rate limiting works correctly behind proxies
- [ ] Harden `htmlError()` in `src/admin-app.ts`: rename parameter to `safeHtml` and add JSDoc warning that callers must pre-escape all interpolated values, or add an `escapeHtml` call on the message and split caller call sites into raw-html and string variants
- [ ] (Optional / low priority) Document that session IP binding is not implemented and is by design; add a note in CLAUDE.md
- [ ] Verify `npm run check` passes

---

## Status

| Phase                                      | Status   | Commit |
| ------------------------------------------ | -------- | ------ |
| 1 — Dependency upgrades                    | complete | —      |
| 2 — SSRF hardening                         | complete | —      |
| 3 — Timing-safe CSRF                       | complete | —      |
| 4 — OAuth rate limiting & state validation | pending  | —      |
| 5 — Admin hardening                        | pending  | —      |
