/**
 * Darboon client — a single, dependency-light TypeScript example that exercises
 * every client-facing flow of the Darboon IDP.
 *
 * It uses only the global `fetch` (Node >= 18) and `readline` (for OTP input).
 * `jose` is loaded lazily and only if you call `verifyAccessToken()` — in real
 * services prefer the `@darboon/nestjs-verifier` SDK.
 *
 * Run:
 *   npx tsx examples/darboon-client.ts
 *   # or: ts-node examples/darboon-client.ts
 *
 * Configure via env (all optional — sensible local defaults below):
 *   DARBOON_URL   (default http://localhost:3000)
 *   CLIENT_ID     (default darboon-admin)
 *   USERNAME      (default admin@example.com)
 *   PASSWORD      (default change-me-immediately)
 *   PHONE         (default +15551234567)
 *   ADMIN_API_KEY (for introspection; optional)
 */

import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';

// ── Types mirroring Darboon's responses ───────────────────────────────────────
export interface TokenSet {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token: string;
  scope?: string;
  id_token?: string;
}

export interface MfaRequired {
  mfa_required: true;
  mfa_token: string;
  factors: string[];
}

export type LoginOutcome = TokenSet | MfaRequired;

export function isMfaRequired(o: LoginOutcome): o is MfaRequired {
  return (o as MfaRequired).mfa_required === true;
}

interface OAuthErrorBody {
  error?: string;
  error_description?: string;
  message?: unknown;
}

/** Thrown for any non-2xx response, carrying the parsed OAuth/HTTP error body. */
export class DarboonError extends Error {
  constructor(
    readonly status: number,
    readonly body: OAuthErrorBody,
  ) {
    super(body.error_description ?? body.error ?? `HTTP ${status}`);
    this.name = 'DarboonError';
  }
}

// ── The client ────────────────────────────────────────────────────────────────
export class DarboonClient {
  private accessToken?: string;
  private refreshToken?: string;

  constructor(
    private readonly baseUrl: string,
    private readonly clientId: string,
    /** Optional client secret for confidential clients. */
    private readonly clientSecret?: string,
  ) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  getTokens(): { accessToken?: string; refreshToken?: string } {
    return { accessToken: this.accessToken, refreshToken: this.refreshToken };
  }

  private rememberTokens(t: TokenSet): TokenSet {
    this.accessToken = t.access_token;
    this.refreshToken = t.refresh_token; // rotated on every refresh — always keep latest
    return t;
  }

  private async request<T>(
    path: string,
    init: RequestInit & { json?: unknown } = {},
  ): Promise<T> {
    const { json, headers, ...rest } = init;
    const res = await fetch(`${this.baseUrl}${path}`, {
      ...rest,
      headers: {
        ...(json !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(headers ?? {}),
      },
      body: json !== undefined ? JSON.stringify(json) : (rest.body ?? null),
    });
    const text = await res.text();
    const parsed = text ? JSON.parse(text) : {};
    if (!res.ok) {
      throw new DarboonError(res.status, parsed as OAuthErrorBody);
    }
    return parsed as T;
  }

  // ── OIDC discovery ──────────────────────────────────────────────────────────
  discovery(): Promise<Record<string, unknown>> {
    return this.request('/.well-known/openid-configuration');
  }

  jwks(): Promise<{ keys: unknown[] }> {
    return this.request('/.well-known/jwks.json');
  }

  // ── Self-service registration & verification ────────────────────────────────
  register(dto: {
    email?: string;
    phone?: string;
    username?: string;
    password: string;
  }): Promise<{ userId: string; status: string }> {
    return this.request('/register', { method: 'POST', json: dto });
  }

  confirmEmail(token: string): Promise<{ verified: true }> {
    return this.request('/verify/email/confirm', {
      method: 'POST',
      json: { token },
    });
  }

  requestPhoneVerification(phone: string): Promise<{ sent: true }> {
    return this.request('/verify/phone/request', {
      method: 'POST',
      json: { phone },
    });
  }

  confirmPhone(phone: string, code: string): Promise<{ verified: true }> {
    return this.request('/verify/phone/confirm', {
      method: 'POST',
      json: { phone, code },
    });
  }

  // ── Password login (may return an MFA challenge) ────────────────────────────
  async loginPassword(
    identifier: string,
    password: string,
    scope = 'openid profile email',
  ): Promise<LoginOutcome> {
    const outcome = await this.request<LoginOutcome>('/oauth/token', {
      method: 'POST',
      json: {
        grant_type: 'password',
        client_id: this.clientId,
        client_secret: this.clientSecret,
        username: identifier,
        password,
        scope,
      },
    });
    if (!isMfaRequired(outcome)) this.rememberTokens(outcome);
    return outcome;
  }

  // ── OTP: request a code, then exchange it (login or MFA completion) ──────────
  requestOtp(params: {
    identifier?: string;
    mfaToken?: string;
  }): Promise<{ otp_sent: true; expires_in: number }> {
    return this.request('/auth/otp/request', {
      method: 'POST',
      json: {
        client_id: this.clientId,
        identifier: params.identifier,
        mfa_token: params.mfaToken,
      },
    });
  }

  async otpGrant(params: {
    identifier: string;
    otpCode: string;
    mfaToken?: string;
    scope?: string;
  }): Promise<TokenSet> {
    const tokens = await this.request<TokenSet>('/oauth/token', {
      method: 'POST',
      json: {
        grant_type: 'urn:darboon:otp',
        client_id: this.clientId,
        client_secret: this.clientSecret,
        identifier: params.identifier,
        otp_code: params.otpCode,
        mfa_token: params.mfaToken,
        scope: params.scope,
      },
    });
    return this.rememberTokens(tokens);
  }

  // ── Refresh (rotating — old token becomes invalid) ──────────────────────────
  async refresh(): Promise<TokenSet> {
    if (!this.refreshToken) throw new Error('No refresh token stored');
    const tokens = await this.request<TokenSet>('/oauth/token', {
      method: 'POST',
      json: {
        grant_type: 'refresh_token',
        client_id: this.clientId,
        client_secret: this.clientSecret,
        refresh_token: this.refreshToken,
      },
    });
    return this.rememberTokens(tokens);
  }

  // ── OIDC userinfo (uses the current access token) ───────────────────────────
  userinfo(): Promise<Record<string, unknown>> {
    return this.request('/userinfo', {
      headers: { Authorization: `Bearer ${this.accessToken}` },
    });
  }

  // ── Logout (revokes the refresh-token family) ───────────────────────────────
  async logout(): Promise<void> {
    await this.request('/auth/logout', {
      method: 'POST',
      headers: { Authorization: `Bearer ${this.accessToken}` },
      json: { refresh_token: this.refreshToken },
    });
    this.accessToken = undefined;
    this.refreshToken = undefined;
  }

  // ── RFC 7009 revoke / RFC 7662 introspect ───────────────────────────────────
  revoke(
    token: string,
    hint: 'access_token' | 'refresh_token' = 'refresh_token',
  ): Promise<{ revoked: true }> {
    return this.request('/oauth/revoke', {
      method: 'POST',
      json: {
        client_id: this.clientId,
        client_secret: this.clientSecret,
        token,
        token_type_hint: hint,
      },
    });
  }

  introspect(
    token: string,
    apiKey: string,
  ): Promise<{ active: boolean; sub?: string; roles?: string[] }> {
    return this.request('/oauth/introspect', {
      method: 'POST',
      headers: { 'X-API-Key': apiKey },
      json: { token },
    });
  }

  // ── Password recovery ───────────────────────────────────────────────────────
  forgotPassword(identifier: string): Promise<{ sent: true }> {
    return this.request('/recovery/forgot-password', {
      method: 'POST',
      json: { identifier },
    });
  }

  resetPassword(params: {
    token?: string;
    identifier?: string;
    code?: string;
    newPassword: string;
  }): Promise<{ reset: true }> {
    return this.request('/recovery/reset-password', {
      method: 'POST',
      json: params,
    });
  }

  // ── Sign in with Google (redirect-only) ─────────────────────────────────────
  /** Build the URL to open in a browser; tokens come back in the callback fragment. */
  googleInitiateUrl(redirectUri: string): string {
    const q = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: redirectUri,
    });
    return `${this.baseUrl}/auth/google/initiate?${q.toString()}`;
  }

  /**
   * Parse the tokens Darboon places in the callback URL fragment:
   * https://app/callback#access_token=…&refresh_token=…&token_type=Bearer&expires_in=900
   */
  consumeGoogleCallback(callbackUrl: string): TokenSet {
    const fragment = callbackUrl.split('#')[1] ?? '';
    const p = new URLSearchParams(fragment);
    const tokens: TokenSet = {
      access_token: p.get('access_token') ?? '',
      refresh_token: p.get('refresh_token') ?? '',
      token_type: 'Bearer',
      expires_in: Number(p.get('expires_in') ?? 0),
    };
    return this.rememberTokens(tokens);
  }

  // ── Resource-service side: verify an access token against the JWKS ──────────
  /**
   * Demonstrates how a downstream service verifies a Darboon token. Lazily uses
   * `jose`; in a NestJS service prefer `@darboon/nestjs-verifier`.
   */
  async verifyAccessToken(token: string, audience: string): Promise<unknown> {
    // Soft dependency: `pnpm add jose` to use this, or prefer @darboon/nestjs-verifier.
    const specifier = 'jose';
    const jose: any = await import(specifier);
    const doc = (await this.discovery()) as { issuer: string; jwks_uri: string };
    const jwks = jose.createRemoteJWKSet(new URL(doc.jwks_uri));
    const { payload } = await jose.jwtVerify(token, jwks, {
      issuer: doc.issuer,
      audience,
    });
    return payload;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Decode (NOT verify) a JWT payload, for display/debugging only. */
export function decodeJwt(token: string): Record<string, unknown> {
  const [, payload] = token.split('.');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
}

async function prompt(question: string): Promise<string> {
  const rl = createInterface({ input, output });
  try {
    return (await rl.question(question)).trim();
  } finally {
    rl.close();
  }
}

// ── Demo runner: walks through every flow ──────────────────────────────────────
async function main(): Promise<void> {
  const cfg = {
    url: process.env.DARBOON_URL ?? 'http://localhost:3000',
    clientId: process.env.CLIENT_ID ?? 'darboon-admin',
    username: process.env.USERNAME ?? 'admin@example.com',
    password: process.env.PASSWORD ?? 'change-me-immediately',
    phone: process.env.PHONE ?? '+15551234567',
    adminApiKey: process.env.ADMIN_API_KEY,
  };

  const client = new DarboonClient(cfg.url, cfg.clientId);

  console.log(`\n▶ Darboon @ ${cfg.url} (client_id=${cfg.clientId})\n`);

  // 1) OIDC discovery
  const disco = (await client.discovery()) as { issuer: string };
  console.log('① discovery     → issuer:', disco.issuer);

  // 2) Password login (handles the MFA branch)
  console.log('② password login…');
  const outcome = await client.loginPassword(cfg.username, cfg.password);

  if (isMfaRequired(outcome)) {
    console.log('   MFA required, factors:', outcome.factors.join(', '));
    await client.requestOtp({ mfaToken: outcome.mfa_token });
    const code = await prompt('   Enter the OTP sent to your phone: ');
    await client.otpGrant({
      identifier: cfg.phone,
      otpCode: code,
      mfaToken: outcome.mfa_token,
    });
    console.log('   MFA complete ✔');
  } else {
    const claims = decodeJwt(outcome.access_token);
    console.log('   logged in ✔  roles:', JSON.stringify(claims.roles));
  }

  // 3) Userinfo
  const me = await client.userinfo();
  console.log('③ userinfo      → sub:', me.sub, 'email:', me.email);

  // 4) Refresh (rotation)
  const before = client.getTokens().refreshToken;
  await client.refresh();
  const after = client.getTokens().refreshToken;
  console.log('④ refresh       → rotated:', before !== after);

  // 5) Introspection (optional — needs an admin/resource API key)
  if (cfg.adminApiKey) {
    const { accessToken } = client.getTokens();
    const result = await client.introspect(accessToken!, cfg.adminApiKey);
    console.log('⑤ introspect    → active:', result.active);
  } else {
    console.log('⑤ introspect    → skipped (set ADMIN_API_KEY to try)');
  }

  // 6) Reuse-detection demo: replaying the OLD refresh token must fail and
  //    revoke the whole family.
  if (before) {
    const res = await fetch(`${cfg.url}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'refresh_token',
        client_id: cfg.clientId,
        refresh_token: before,
      }),
    });
    const body = (await res.json()) as OAuthErrorBody;
    console.log(
      res.ok
        ? '⑥ reuse check   → UNEXPECTED success'
        : `⑥ reuse check   → correctly rejected: ${body.error}`,
    );
  }

  // 7) Logout
  await client.logout();
  console.log('⑦ logout        → done ✔');

  // ── The remaining flows are interactive/side-effecting; shown as snippets ──
  console.log('\nOther flows (call these as needed):');
  console.log('  • register:        client.register({ email, phone, password })');
  console.log('  • verify email:    client.confirmEmail(tokenFromEmail)');
  console.log('  • verify phone:    client.requestPhoneVerification(phone) → confirmPhone(phone, code)');
  console.log('  • OTP login:       client.requestOtp({ identifier }) → otpGrant({ identifier, otpCode })');
  console.log('  • forgot/reset:    client.forgotPassword(id) → resetPassword({ token|code, newPassword })');
  console.log('  • google:          open client.googleInitiateUrl(redirectUri), then consumeGoogleCallback(url)');
  console.log('  • verify (svc):    client.verifyAccessToken(jwt, audience)\n');
}

// Only run the demo when executed directly (not when imported).
if (require.main === module) {
  main().catch((err) => {
    if (err instanceof DarboonError) {
      console.error(`\n✗ Darboon error ${err.status}:`, err.body);
    } else {
      console.error('\n✗', err);
    }
    process.exit(1);
  });
}
