import { createHash, randomBytes } from "node:crypto";
import { lookup } from "node:dns";
import { isIP } from "node:net";
import type { DatabaseSync } from "node:sqlite";
import { hash as argon2Hash, verify as argon2Verify } from "@node-rs/argon2";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { Agent, request } from "undici";
import type { GatewayConfig, OAuthConfig } from "./config.js";
import { isPrivateNetworkAddress } from "./config.js";
import { issueToken } from "./oauth-token-store.js";

const TX_COOKIE = "mcp_oauth_tx";
const MAX_CLIENT_METADATA_BYTES = 65_536;
const ARGON2_OPTIONS = { memoryCost: 65_536, timeCost: 3, parallelism: 1 };

interface ClientMetadata {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  token_endpoint_auth_method: "none";
}

interface AuthorizationTransaction {
  tokenHash: string;
  csrfToken: string;
  clientId: string;
  redirectUri: string;
  resource: string;
  scope: string;
  state: string | null;
  codeChallenge: string;
  authenticated: number;
}

export interface RegisterOAuthOptions {
  loadClientMetadata?: (clientId: string) => Promise<ClientMetadata>;
}

export function registerOAuthAuthorizationServer(
  app: FastifyInstance,
  config: GatewayConfig,
  db: DatabaseSync,
  options: RegisterOAuthOptions = {},
): void {
  const oauth = config.oauth;
  upsertStaticClients(db, oauth);
  pruneExpiredOAuthRecords(db);
  const loadClientMetadata = options.loadClientMetadata ?? fetchClientMetadata;
  const cleanupInterval = setInterval(
    () => pruneExpiredOAuthRecords(db),
    3_600_000,
  );
  cleanupInterval.unref();
  app.addHook("onClose", async () => clearInterval(cleanupInterval));

  app.addHook("onSend", async (_request, reply) => {
    reply.header("X-Frame-Options", "DENY");
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header(
      "Content-Security-Policy",
      "default-src 'self'; frame-ancestors 'none'",
    );
    reply.header("Cache-Control", "no-store");
  });

  app.get("/.well-known/oauth-authorization-server", async (_request, reply) =>
    reply.send(metadata(oauth)),
  );

  app.post("/oauth/register", async (request, reply) => {
    if (registrationRateLimited(db, oauth, request.ip)) {
      return oauthError(
        reply,
        429,
        "slow_down",
        "Registration rate limit exceeded",
      );
    }
    recordRegistrationAttempt(db, request.ip);
    const body = asRecord(request.body);
    const parsed = validateClientMetadata(body);
    if (!parsed) {
      return oauthError(reply, 400, "invalid_client_metadata");
    }
    const clientId = randomBytes(24).toString("base64url");
    saveClient(db, { ...parsed, client_id: clientId }, "dynamic");
    return reply.code(201).send({ ...parsed, client_id: clientId });
  });

  app.get("/oauth/authorize", async (request, reply) => {
    const query = stringRecord(request.query);
    if (!query) {
      return oauthError(
        reply,
        400,
        "invalid_request",
        "Query parameters must be singular strings",
      );
    }
    const validated = await validateAuthorizationRequest(
      db,
      config,
      query,
      loadClientMetadata,
    );
    if ("error" in validated) {
      return oauthError(reply, 400, "invalid_request", validated.error);
    }
    const tx = createAuthorizationTransaction(db, oauth, validated);
    setTransactionCookie(reply, oauth, tx.plaintext);
    return reply
      .type("text/html")
      .send(
        oauthPage(
          "Sign in",
          loginPageHtml(validated.client.client_name, tx.csrfToken),
        ),
      );
  });

  app.post("/oauth/authorize/login", async (request, reply) => {
    const tx = requireTransaction(db, request, reply);
    if (!tx) return;
    const body = stringRecord(request.body);
    if (!body) return oauthError(reply, 400, "invalid_request");
    if (!validCsrf(tx, body._csrf)) {
      return oauthError(reply, 403, "access_denied", "Invalid CSRF token");
    }
    const clientName = getClient(db, tx.clientId)?.client_name ?? tx.clientId;
    const rerender = (code: number, error: string) =>
      reply
        .code(code)
        .type("text/html")
        .send(
          oauthPage("Sign in", loginPageHtml(clientName, tx.csrfToken, error)),
        );
    if (oauthLoginRateLimited(db, oauth, request.ip)) {
      return rerender(429, "Too many login attempts. Please try again later.");
    }
    if (!(await verifyOAuthUserPassword(db, body.password ?? ""))) {
      recordOAuthLoginAttempt(db, request.ip, false);
      return rerender(401, "Incorrect password.");
    }
    recordOAuthLoginAttempt(db, request.ip, true);
    db.prepare(
      "UPDATE oauth_authorization_transactions SET authenticated = 1 WHERE token_hash = ?",
    ).run(tx.tokenHash);
    return reply
      .type("text/html")
      .send(
        oauthPage(
          "Allow access?",
          consentPageHtml(clientName, tx.resource, tx.scope, tx.csrfToken),
        ),
      );
  });

  app.post("/oauth/authorize/consent", async (request, reply) => {
    const tx = requireTransaction(db, request, reply);
    if (!tx) return;
    const body = stringRecord(request.body);
    if (!body) return oauthError(reply, 400, "invalid_request");
    if (!validCsrf(tx, body._csrf) || tx.authenticated !== 1) {
      return oauthError(
        reply,
        403,
        "access_denied",
        "Invalid authorization transaction",
      );
    }
    if (body.decision !== "approve") {
      deleteAuthorizationTransaction(db, tx.tokenHash);
      clearTransactionCookie(reply, oauth);
      return reply.redirect(
        appendRedirectParams(tx.redirectUri, {
          error: "access_denied",
          state: tx.state,
          iss: oauth.issuer,
        }),
      );
    }
    const code = inTransaction(db, () => {
      deleteAuthorizationTransaction(db, tx.tokenHash);
      return issueAuthorizationCode(db, oauth, tx);
    });
    clearTransactionCookie(reply, oauth);
    return reply.redirect(
      appendRedirectParams(tx.redirectUri, {
        code,
        state: tx.state,
        iss: oauth.issuer,
      }),
    );
  });

  app.post("/oauth/token", async (request, reply) => {
    const body = stringRecord(request.body);
    if (!body) return oauthError(reply, 400, "invalid_request");
    if (body.grant_type === "authorization_code") {
      const redeemed = redeemAuthorizationCode(db, config, body);
      return "error" in redeemed
        ? oauthError(reply, 400, "invalid_grant", redeemed.error)
        : reply.send(redeemed);
    }
    if (body.grant_type === "refresh_token") {
      const redeemed = redeemRefreshToken(db, config, body);
      return "error" in redeemed
        ? oauthError(reply, 400, "invalid_grant", redeemed.error)
        : reply.send(redeemed);
    }
    return oauthError(reply, 400, "unsupported_grant_type");
  });

  app.post("/oauth/revoke", async (request, reply) => {
    const body = stringRecord(request.body);
    if (!body) return oauthError(reply, 400, "invalid_request");
    if (!body.token) return oauthError(reply, 400, "invalid_request");
    revokePlaintextToken(db, body.token);
    return reply.code(200).send();
  });
}

export async function setOAuthUserPassword(
  db: DatabaseSync,
  password: string,
): Promise<void> {
  const passwordHash = await argon2Hash(password, ARGON2_OPTIONS);
  db.prepare(
    `INSERT INTO oauth_user_credentials (id, password_hash)
     VALUES (1, ?)
     ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash,
                                   updated_at = unixepoch()`,
  ).run(passwordHash);
}

// Cached dummy hash so verifyOAuthUserPassword always runs argon2 regardless
// of whether credentials exist, preventing timing-based enumeration.
let _oauthDummyHash: string | undefined;
async function getOauthDummyHash(): Promise<string> {
  _oauthDummyHash ??= await argon2Hash("", ARGON2_OPTIONS);
  return _oauthDummyHash;
}

export async function verifyOAuthUserPassword(
  db: DatabaseSync,
  password: string,
): Promise<boolean> {
  const row = db
    .prepare("SELECT password_hash FROM oauth_user_credentials WHERE id = 1")
    .get() as { password_hash: string } | undefined;
  if (row) {
    return argon2Verify(row.password_hash, password);
  }
  await argon2Verify(await getOauthDummyHash(), password).catch(() => {});
  return false;
}

function metadata(oauth: OAuthConfig) {
  return {
    issuer: oauth.issuer,
    authorization_endpoint: `${oauth.issuer}/oauth/authorize`,
    token_endpoint: `${oauth.issuer}/oauth/token`,
    registration_endpoint: `${oauth.issuer}/oauth/register`,
    revocation_endpoint: `${oauth.issuer}/oauth/revoke`,
    scopes_supported: ["mcp"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    client_id_metadata_document_supported: true,
  };
}

async function validateAuthorizationRequest(
  db: DatabaseSync,
  config: GatewayConfig,
  query: Record<string, string | undefined>,
  loadClientMetadata: (clientId: string) => Promise<ClientMetadata>,
) {
  if (
    query.response_type !== "code" ||
    !query.client_id ||
    !query.redirect_uri ||
    !query.resource ||
    !query.code_challenge ||
    query.code_challenge_method !== "S256"
  ) {
    return {
      error:
        "response_type, client_id, redirect_uri, resource, and PKCE S256 are required",
    };
  }
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(query.code_challenge)) {
    return { error: "Invalid PKCE code challenge" };
  }
  if (!validScope(query.scope ?? "")) {
    return { error: "Invalid OAuth scope" };
  }
  if (!resourceRoute(config, query.resource)) {
    return { error: "Invalid resource indicator" };
  }
  const client = await resolveClient(db, query.client_id, loadClientMetadata);
  if (!client || !client.redirect_uris.includes(query.redirect_uri)) {
    return { error: "Unknown client or redirect URI mismatch" };
  }
  return {
    client,
    redirectUri: query.redirect_uri,
    resource: query.resource,
    scope: normalizeScope(query.scope ?? ""),
    state: query.state ?? null,
    codeChallenge: query.code_challenge,
  };
}

function createAuthorizationTransaction(
  db: DatabaseSync,
  oauth: OAuthConfig,
  input: {
    client: ClientMetadata;
    redirectUri: string;
    resource: string;
    scope: string;
    state: string | null;
    codeChallenge: string;
  },
) {
  const plaintext = randomToken();
  const csrfToken = randomToken();
  db.prepare(
    `INSERT INTO oauth_authorization_transactions
     (token_hash, csrf_token, client_id, redirect_uri, resource, scope, state,
      code_challenge, code_challenge_method, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'S256', ?)`,
  ).run(
    sha256Hex(plaintext),
    csrfToken,
    input.client.client_id,
    input.redirectUri,
    input.resource,
    input.scope,
    input.state,
    input.codeChallenge,
    now() + oauth.authorizationTransactionTtlSeconds,
  );
  return { plaintext, csrfToken };
}

function requireTransaction(
  db: DatabaseSync,
  request: FastifyRequest,
  reply: FastifyReply,
): AuthorizationTransaction | undefined {
  const token = request.cookies[TX_COOKIE];
  if (!token) {
    void oauthError(
      reply,
      400,
      "invalid_request",
      "Missing authorization transaction",
    );
    return undefined;
  }
  const row = db
    .prepare(
      `SELECT token_hash AS tokenHash, csrf_token AS csrfToken, client_id AS clientId,
              redirect_uri AS redirectUri, resource, scope, state,
              code_challenge AS codeChallenge, authenticated
       FROM oauth_authorization_transactions
       WHERE token_hash = ? AND expires_at > ?`,
    )
    .get(sha256Hex(token), now()) as AuthorizationTransaction | undefined;
  if (!row) {
    void oauthError(
      reply,
      400,
      "invalid_request",
      "Expired authorization transaction",
    );
  }
  return row;
}

function issueAuthorizationCode(
  db: DatabaseSync,
  oauth: OAuthConfig,
  tx: AuthorizationTransaction,
): string {
  const code = randomToken();
  db.prepare(
    `INSERT INTO oauth_authorization_codes
     (code_hash, client_id, redirect_uri, resource, scope, code_challenge,
      code_challenge_method, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, 'S256', ?)`,
  ).run(
    sha256Hex(code),
    tx.clientId,
    tx.redirectUri,
    tx.resource,
    tx.scope,
    tx.codeChallenge,
    now() + oauth.authorizationCodeTtlSeconds,
  );
  return code;
}

function redeemAuthorizationCode(
  db: DatabaseSync,
  config: GatewayConfig,
  body: Record<string, string | undefined>,
) {
  if (
    !body.code ||
    !body.client_id ||
    !body.redirect_uri ||
    !body.resource ||
    !body.code_verifier
  ) {
    return { error: "Missing authorization code parameters" };
  }
  const row = db
    .prepare(
      `SELECT id, client_id AS clientId, redirect_uri AS redirectUri, resource,
              scope, code_challenge AS codeChallenge
       FROM oauth_authorization_codes
       WHERE code_hash = ? AND consumed_at IS NULL AND expires_at > ?`,
    )
    .get(sha256Hex(body.code), now()) as
    | {
        id: number;
        clientId: string;
        redirectUri: string;
        resource: string;
        scope: string;
        codeChallenge: string;
      }
    | undefined;
  if (
    !row ||
    row.clientId !== body.client_id ||
    row.redirectUri !== body.redirect_uri ||
    row.resource !== body.resource ||
    !validPkceVerifier(body.code_verifier) ||
    pkceChallenge(body.code_verifier) !== row.codeChallenge
  ) {
    return { error: "Invalid authorization code" };
  }
  return inTransaction(db, () => {
    const consumed = db
      .prepare(
        "UPDATE oauth_authorization_codes SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL",
      )
      .run(now(), row.id);
    if (consumed.changes !== 1) return { error: "Invalid authorization code" };
    return issueProtocolTokens(
      db,
      config,
      row.clientId,
      row.resource,
      row.scope,
    );
  });
}

function redeemRefreshToken(
  db: DatabaseSync,
  config: GatewayConfig,
  body: Record<string, string | undefined>,
) {
  if (!body.refresh_token || !body.client_id || !body.resource) {
    return { error: "Missing refresh token parameters" };
  }
  const row = db
    .prepare(
      `SELECT id, family_id AS familyId, client_id AS clientId, resource, scope,
              expires_at AS expiresAt, consumed_at AS consumedAt, revoked_at AS revokedAt
       FROM oauth_refresh_tokens WHERE token_hash = ?`,
    )
    .get(sha256Hex(body.refresh_token)) as
    | {
        id: number;
        familyId: string;
        clientId: string;
        resource: string;
        scope: string;
        expiresAt: number;
        consumedAt: number | null;
        revokedAt: number | null;
      }
    | undefined;
  if (
    !row ||
    row.clientId !== body.client_id ||
    row.resource !== body.resource
  ) {
    return { error: "Invalid refresh token" };
  }
  if (row.consumedAt !== null) {
    inTransaction(db, () => revokeRefreshFamily(db, row.familyId));
    return { error: "Refresh token reuse detected" };
  }
  if (row.revokedAt !== null || row.expiresAt <= now()) {
    return { error: "Invalid refresh token" };
  }
  return inTransaction(db, () => {
    const consumed = db
      .prepare(
        "UPDATE oauth_refresh_tokens SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL",
      )
      .run(now(), row.id);
    if (consumed.changes !== 1) {
      revokeRefreshFamily(db, row.familyId);
      return { error: "Refresh token reuse detected" };
    }
    return issueProtocolTokens(
      db,
      config,
      row.clientId,
      row.resource,
      row.scope,
      row.familyId,
    );
  });
}

function issueProtocolTokens(
  db: DatabaseSync,
  config: GatewayConfig,
  clientId: string,
  resource: string,
  scope: string,
  familyId = randomToken(),
) {
  const route = resourceRoute(config, resource);
  if (!route) return { error: "Invalid resource indicator" };
  const expiresIn = config.oauth.accessTokenTtlSeconds;
  const access = issueToken(db, {
    description: `OAuth client ${clientId}`,
    scope,
    routes: [route],
    expiresAt: now() + expiresIn,
    refreshFamilyId: familyId,
  });
  const refreshToken = randomToken();
  db.prepare(
    `INSERT INTO oauth_refresh_tokens
     (token_hash, family_id, client_id, resource, scope, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(
    sha256Hex(refreshToken),
    familyId,
    clientId,
    resource,
    scope,
    now() + config.oauth.refreshTokenTtlSeconds,
  );
  return {
    access_token: access.plaintext,
    token_type: "Bearer",
    expires_in: expiresIn,
    refresh_token: refreshToken,
    resource,
    scope,
  };
}

function revokePlaintextToken(db: DatabaseSync, plaintext: string): void {
  const tokenHash = sha256Hex(plaintext);
  db.prepare(
    "UPDATE oauth_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
  ).run(now(), tokenHash);
  const refresh = db
    .prepare(
      "SELECT family_id AS familyId FROM oauth_refresh_tokens WHERE token_hash = ?",
    )
    .get(tokenHash) as { familyId: string } | undefined;
  if (refresh) revokeRefreshFamily(db, refresh.familyId);
}

function revokeRefreshFamily(db: DatabaseSync, familyId: string): void {
  db.prepare(
    "UPDATE oauth_refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL",
  ).run(now(), familyId);
  db.prepare(
    "UPDATE oauth_tokens SET revoked_at = ? WHERE refresh_family_id = ? AND revoked_at IS NULL",
  ).run(now(), familyId);
}

function upsertStaticClients(db: DatabaseSync, oauth: OAuthConfig): void {
  inTransaction(db, () => {
    db.prepare("DELETE FROM oauth_clients WHERE source = 'static'").run();
    for (const client of oauth.staticClients) {
      saveClient(
        db,
        {
          client_id: client.clientId,
          client_name: client.clientName,
          redirect_uris: client.redirectUris,
          token_endpoint_auth_method: "none",
        },
        "static",
      );
    }
  });
}

async function resolveClient(
  db: DatabaseSync,
  clientId: string,
  loader: (clientId: string) => Promise<ClientMetadata>,
): Promise<ClientMetadata | undefined> {
  const stored = getClient(db, clientId);
  if (stored) return stored;
  if (!clientId.startsWith("https://")) return undefined;
  try {
    const fetched = await loader(clientId);
    if (fetched.client_id !== clientId) return undefined;
    saveClient(db, fetched, "metadata_document");
    return fetched;
  } catch {
    return undefined;
  }
}

function getClient(
  db: DatabaseSync,
  clientId: string,
): ClientMetadata | undefined {
  const row = db
    .prepare(
      `SELECT client_id, client_name, redirect_uris, token_endpoint_auth_method
       FROM oauth_clients WHERE client_id = ?`,
    )
    .get(clientId) as
    | {
        client_id: string;
        client_name: string;
        redirect_uris: string;
        token_endpoint_auth_method: "none";
      }
    | undefined;
  return row
    ? { ...row, redirect_uris: JSON.parse(row.redirect_uris) as string[] }
    : undefined;
}

function saveClient(
  db: DatabaseSync,
  client: ClientMetadata,
  source: string,
): void {
  db.prepare(
    `INSERT INTO oauth_clients
     (client_id, client_name, redirect_uris, token_endpoint_auth_method, source)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(client_id) DO UPDATE SET client_name = excluded.client_name,
       redirect_uris = excluded.redirect_uris,
       token_endpoint_auth_method = excluded.token_endpoint_auth_method,
       source = excluded.source`,
  ).run(
    client.client_id,
    client.client_name,
    JSON.stringify(client.redirect_uris),
    client.token_endpoint_auth_method,
    source,
  );
}

function validateClientMetadata(
  body: Record<string, unknown>,
): Omit<ClientMetadata, "client_id"> | undefined {
  const redirectUris = body.redirect_uris;
  if (
    !Array.isArray(redirectUris) ||
    redirectUris.length === 0 ||
    redirectUris.some(
      (uri) => typeof uri !== "string" || !validRedirectUri(uri),
    ) ||
    (body.token_endpoint_auth_method !== undefined &&
      body.token_endpoint_auth_method !== "none")
  ) {
    return undefined;
  }
  return {
    client_name:
      typeof body.client_name === "string" && body.client_name
        ? body.client_name
        : "Dynamic OAuth Client",
    redirect_uris: redirectUris as string[],
    token_endpoint_auth_method: "none",
  };
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function stringRecord(
  value: unknown,
): Record<string, string | undefined> | undefined {
  const record = asRecord(value);
  if (
    Object.values(record).some(
      (item) => item !== undefined && typeof item !== "string",
    )
  ) {
    return undefined;
  }
  return record as Record<string, string | undefined>;
}

export async function fetchClientMetadata(
  clientId: string,
): Promise<ClientMetadata> {
  const url = new URL(clientId);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.hash ||
    isDisallowedHostname(url.hostname)
  ) {
    throw new Error("Client metadata URL must be a public HTTPS URL");
  }
  const dispatcher = publicNetworkDispatcher();
  try {
    const response = await request(url, {
      dispatcher,
      headersTimeout: 5_000,
      bodyTimeout: 5_000,
    });
    if (response.statusCode !== 200)
      throw new Error("Client metadata fetch failed");
    let text = "";
    for await (const chunk of response.body) {
      text += chunk.toString();
      if (Buffer.byteLength(text) > MAX_CLIENT_METADATA_BYTES) {
        throw new Error("Client metadata document too large");
      }
    }
    const document = JSON.parse(text) as Record<string, unknown>;
    if (document.client_id !== clientId) {
      throw new Error("Client metadata document client_id mismatch");
    }
    const parsed = validateClientMetadata(document);
    if (!parsed) throw new Error("Invalid client metadata document");
    return { ...parsed, client_id: clientId };
  } finally {
    await dispatcher.close();
  }
}

function publicNetworkDispatcher(): Agent {
  return new Agent({
    connect: {
      timeout: 5_000,
      lookup: (hostname, _options, callback) => {
        lookup(hostname, { all: true, verbatim: true }, (error, addresses) => {
          if (error) return callback(error, "", 0);
          const address = addresses.find(
            (candidate) => !isDisallowedHostname(candidate.address),
          );
          return address
            ? callback(null, address.address, address.family)
            : callback(
                new Error("Client metadata hostname did not resolve publicly"),
                "",
                0,
              );
        });
      },
    },
  });
}

export function isDisallowedMetadataHostname(hostname: string): boolean {
  hostname =
    hostname.startsWith("[") && hostname.endsWith("]")
      ? hostname.slice(1, -1)
      : hostname;
  if (hostname === "localhost") return true;
  if (!isIP(hostname)) return false;
  if (isPrivateNetworkAddress(hostname)) return true;
  if (hostname.includes(":")) {
    const normalized = hostname.toLowerCase();
    return (
      normalized === "::" ||
      normalized === "::1" ||
      normalized.startsWith("fe80:") ||
      normalized.startsWith("fec") ||
      normalized.startsWith("::ffff:") ||
      normalized.startsWith("ff")
    );
  }
  const [first, second] = hostname.split(".").map(Number);
  return (
    first === 0 ||
    first === 127 ||
    (first === 100 && second >= 64 && second <= 127) ||
    hostname.startsWith("169.254.") ||
    (first === 192 && second === 0) ||
    (first === 198 && (second === 18 || second === 19)) ||
    first >= 224
  );
}

const isDisallowedHostname = isDisallowedMetadataHostname;

function oauthLoginRateLimited(
  db: DatabaseSync,
  oauth: OAuthConfig,
  ip: string,
): boolean {
  const row = db
    .prepare(
      `SELECT count(*) AS n, max(created_at) AS latest
       FROM oauth_login_attempts
       WHERE ip_address = ? AND succeeded = 0 AND created_at >= ?`,
    )
    .get(ip, now() - 3_600) as { n: number; latest: number | null };
  return (
    row.n >= oauth.loginLimitPerHour &&
    row.latest !== null &&
    row.latest + oauth.loginLockoutSeconds > now()
  );
}

function recordOAuthLoginAttempt(
  db: DatabaseSync,
  ip: string,
  succeeded: boolean,
): void {
  db.prepare("DELETE FROM oauth_login_attempts WHERE created_at < ?").run(
    now() - 3_600,
  );
  db.prepare(
    "INSERT INTO oauth_login_attempts (ip_address, succeeded) VALUES (?, ?)",
  ).run(ip, succeeded ? 1 : 0);
}

function inTransaction<T>(db: DatabaseSync, operation: () => T): T {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = operation();
    db.exec("COMMIT");
    return result;
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

function pruneExpiredOAuthRecords(db: DatabaseSync): void {
  const current = now();
  db.prepare(
    "DELETE FROM oauth_authorization_transactions WHERE expires_at <= ?",
  ).run(current);
  db.prepare("DELETE FROM oauth_authorization_codes WHERE expires_at <= ?").run(
    current,
  );
  db.prepare("DELETE FROM oauth_refresh_tokens WHERE expires_at <= ?").run(
    current,
  );
  db.prepare("DELETE FROM oauth_login_attempts WHERE created_at < ?").run(
    current - 3_600,
  );
  db.prepare(
    "DELETE FROM oauth_registration_attempts WHERE created_at < ?",
  ).run(current - 3_600);
}

function registrationRateLimited(
  db: DatabaseSync,
  oauth: OAuthConfig,
  ip: string,
): boolean {
  const row = db
    .prepare(
      "SELECT count(*) AS n FROM oauth_registration_attempts WHERE ip_address = ? AND created_at >= ?",
    )
    .get(ip, now() - 3_600) as { n: number };
  return row.n >= oauth.dynamicRegistrationLimitPerHour;
}

function recordRegistrationAttempt(db: DatabaseSync, ip: string): void {
  db.prepare(
    "DELETE FROM oauth_registration_attempts WHERE created_at < ?",
  ).run(now() - 3_600);
  db.prepare(
    "INSERT INTO oauth_registration_attempts (ip_address) VALUES (?)",
  ).run(ip);
}

function resourceRoute(
  config: GatewayConfig,
  resource: string,
): string | undefined {
  return config.routes.find(
    (route) => `${config.security.publicOrigin}${route.path}/mcp` === resource,
  )?.path;
}

function validRedirectUri(uri: string): boolean {
  try {
    const url = new URL(uri);
    return (
      !url.username &&
      !url.password &&
      !url.hash &&
      (url.protocol === "https:" ||
        (url.protocol === "http:" &&
          ["localhost", "127.0.0.1", "::1"].includes(url.hostname)))
    );
  } catch {
    return false;
  }
}

function setTransactionCookie(
  reply: FastifyReply,
  oauth: OAuthConfig,
  token: string,
): void {
  reply.setCookie(TX_COOKIE, token, {
    httpOnly: true,
    secure: !oauth.insecureAllowHttpIssuer,
    sameSite: "lax",
    path: "/oauth/authorize",
  });
}

function clearTransactionCookie(reply: FastifyReply, oauth: OAuthConfig): void {
  reply.clearCookie(TX_COOKIE, {
    secure: !oauth.insecureAllowHttpIssuer,
    path: "/oauth/authorize",
  });
}

function deleteAuthorizationTransaction(
  db: DatabaseSync,
  tokenHash: string,
): void {
  db.prepare(
    "DELETE FROM oauth_authorization_transactions WHERE token_hash = ?",
  ).run(tokenHash);
}

function validCsrf(
  tx: AuthorizationTransaction,
  submitted: string | undefined,
): boolean {
  return submitted !== undefined && submitted === tx.csrfToken;
}

function appendRedirectParams(
  redirectUri: string,
  params: Record<string, string | null>,
): string {
  const url = new URL(redirectUri);
  for (const [key, value] of Object.entries(params)) {
    if (value !== null) url.searchParams.set(key, value);
  }
  return url.toString();
}

function oauthError(
  reply: FastifyReply,
  status: number,
  error: string,
  description?: string,
) {
  return reply.code(status).send({
    error,
    ...(description ? { error_description: description } : {}),
  });
}

function normalizeScope(scope: string): string {
  return [...new Set(scope.split(" ").filter(Boolean))].join(" ");
}

function validScope(scope: string): boolean {
  return scope
    .split(" ")
    .filter(Boolean)
    .every((value) => /^[\x21\x23-\x5b\x5d-\x7e]+$/.test(value));
}

function validPkceVerifier(verifier: string): boolean {
  return /^[A-Za-z0-9\-._~]{43,128}$/.test(verifier);
}

function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier, "utf8").digest("base64url");
}

function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function now(): number {
  return Math.floor(Date.now() / 1000);
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    return (
      { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[
        char
      ] ?? char
    );
  });
}

const OAUTH_CSS = `
*,*::before,*::after{box-sizing:border-box}
:root{
  --bg:#f8fafc;--surface:#ffffff;--surface-2:#f1f5f9;
  --border:#e2e8f0;--border-2:#cbd5e1;
  --text:#0f172a;--text-2:#475569;--muted:#64748b;
  --accent:#2563eb;--accent-h:#1d4ed8;--accent-t:color-mix(in srgb,#2563eb 12%,transparent);
  --danger:#dc2626;--danger-h:#b91c1c;--danger-t:color-mix(in srgb,#dc2626 12%,transparent);
  --shadow:0 1px 3px rgba(0,0,0,.08),0 1px 2px rgba(0,0,0,.05);
  --radius:6px;
}
@media(prefers-color-scheme:dark){:root{
  --bg:#0f172a;--surface:#1e293b;--surface-2:#0f172a;
  --border:#334155;--border-2:#475569;
  --text:#f1f5f9;--text-2:#cbd5e1;--muted:#94a3b8;
  --accent:#3b82f6;--accent-h:#60a5fa;--accent-t:color-mix(in srgb,#3b82f6 15%,transparent);
  --danger:#ef4444;--danger-h:#f87171;--danger-t:color-mix(in srgb,#ef4444 15%,transparent);
  --shadow:0 1px 3px rgba(0,0,0,.4),0 1px 2px rgba(0,0,0,.3);
}}
body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.5}
code{font-family:ui-monospace,'Cascadia Code','Fira Code',monospace;font-size:.85em;background:var(--surface-2);padding:.1em .35em;border-radius:3px;word-break:break-all}
.auth-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem}
.auth-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:2.5rem;width:100%;max-width:420px;box-shadow:var(--shadow)}
.auth-logo{font-size:1rem;font-weight:700;color:var(--accent);margin-bottom:.25rem}
.auth-title{font-size:1.25rem;font-weight:700;margin:0 0 .25rem}
.auth-subtitle{color:var(--muted);font-size:.875rem;margin-bottom:1.75rem}
.form-group{margin-bottom:1.25rem}
.form-label{display:block;font-size:.875rem;font-weight:500;margin-bottom:.375rem}
.form-input{display:block;width:100%;padding:.5rem .75rem;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface);color:var(--text);font-size:.875rem;transition:border-color .15s,outline .15s}
.form-input:focus{outline:2px solid var(--accent);outline-offset:-1px;border-color:var(--accent)}
.btn{display:inline-flex;align-items:center;justify-content:center;padding:.5rem 1rem;border-radius:var(--radius);font-size:.875rem;font-weight:500;cursor:pointer;border:1px solid transparent;line-height:1.4;transition:background .15s,border-color .15s,color .15s}
.btn-primary{background:var(--accent);color:#fff;border-color:var(--accent)}
.btn-primary:hover{background:var(--accent-h);border-color:var(--accent-h)}
.btn-danger-outline{background:transparent;border-color:var(--danger);color:var(--danger)}
.btn-danger-outline:hover{background:var(--danger);color:#fff}
.btn-group{display:flex;gap:.5rem}
.w-full{width:100%}
.alert{padding:.75rem 1rem;border-radius:var(--radius);border-left:4px solid;margin-bottom:1.25rem;font-size:.875rem}
.alert-error{background:var(--danger-t);border-color:var(--danger);color:var(--danger)}
.info-box{border:1px solid var(--border);border-radius:var(--radius);margin-bottom:1.5rem;overflow:hidden}
.info-row{padding:.75rem 1rem;border-bottom:1px solid var(--border);display:flex;flex-direction:column;gap:.2rem}
.info-row:last-child{border-bottom:none}
.info-label{font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.info-value{font-size:.875rem;color:var(--text)}
.scope-badge{display:inline-flex;align-items:center;padding:.15rem .55rem;border-radius:99px;font-size:.75rem;font-weight:600;background:var(--accent-t);color:var(--accent);font-family:ui-monospace,monospace}
`.trim();

function oauthPage(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';base-uri 'self';form-action 'self'">
<title>${escapeHtml(title)} — MCP Gateway</title>
<style>${OAUTH_CSS}</style>
</head>
<body>
<div class="auth-wrap">
<div class="auth-card">
${body}
</div>
</div>
</body>
</html>`;
}

function loginPageHtml(
  clientName: string,
  csrfToken: string,
  error?: string,
): string {
  const errorHtml = error
    ? `<div class="alert alert-error">${escapeHtml(error)}</div>`
    : "";
  return `<div class="auth-logo">MCP Gateway</div>
<h2 class="auth-title">Sign in</h2>
<p class="auth-subtitle"><strong>${escapeHtml(clientName)}</strong> is requesting access to your MCP tools.</p>
${errorHtml}<form method="POST" action="/oauth/authorize/login">
  <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}">
  <div class="form-group">
    <label class="form-label" for="pw">Password</label>
    <input class="form-input" type="password" id="pw" name="password" required autocomplete="current-password" autofocus>
  </div>
  <button type="submit" class="btn btn-primary w-full">Continue</button>
</form>`;
}

function consentPageHtml(
  clientName: string,
  resource: string,
  scope: string,
  csrfToken: string,
): string {
  const resourcePath = (() => {
    try {
      return new URL(resource).pathname;
    } catch {
      return resource;
    }
  })();
  const scopes = scope ? scope.split(" ").filter(Boolean) : [];
  const scopeHtml =
    scopes.length > 0
      ? scopes
          .map((s) => `<span class="scope-badge">${escapeHtml(s)}</span>`)
          .join(" ")
      : "<span style='color:var(--muted)'>(none)</span>";
  return `<div class="auth-logo">MCP Gateway</div>
<h2 class="auth-title">Allow access?</h2>
<p class="auth-subtitle"><strong>${escapeHtml(clientName)}</strong> is requesting permission to use your MCP tools.</p>
<div class="info-box">
  <div class="info-row">
    <div class="info-label">Application</div>
    <div class="info-value">${escapeHtml(clientName)}</div>
  </div>
  <div class="info-row">
    <div class="info-label">Resource</div>
    <div class="info-value"><code>${escapeHtml(resourcePath)}</code></div>
  </div>
  <div class="info-row">
    <div class="info-label">Scopes</div>
    <div class="info-value">${scopeHtml}</div>
  </div>
</div>
<form method="POST" action="/oauth/authorize/consent">
  <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}">
  <div class="btn-group">
    <button type="submit" name="decision" value="approve" class="btn btn-primary w-full">Approve</button>
    <button type="submit" name="decision" value="deny" class="btn btn-danger-outline">Deny</button>
  </div>
</form>`;
}
