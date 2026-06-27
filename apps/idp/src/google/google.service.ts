import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EntityManager } from '@mikro-orm/core';
import { createHash, randomBytes } from 'crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import Redis from 'ioredis';
import { v4 as uuid } from 'uuid';
import {
  Application,
  GrantType,
  Identity,
  IdentityProvider,
  User,
  UserStatus,
} from '../entities';
import { ApplicationsService } from '../applications/applications.service';
import { TokenService, TokenSet } from '../token/token.service';
import { AuditService } from '../audit/audit.service';
import { MetricsService } from '../metrics/metrics.service';
import { InjectRedis } from '../redis/redis.module';
import { OAuthError } from '../common/oauth-error';

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_CERTS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

interface GoogleState {
  applicationId: string;
  dashboardRedirect: string;
  codeVerifier: string;
  nonce: string;
  scope?: string;
}

/**
 * Sign in with Google via redirect callbacks only (no hosted HTML). Darboon
 * builds the consent URL with PKCE + a signed state, exchanges the code, verifies
 * Google's ID token, links/creates a local identity, and mints Darboon tokens.
 */
@Injectable()
export class GoogleService {
  private readonly logger = new Logger(GoogleService.name);
  private readonly googleJwks = createRemoteJWKSet(new URL(GOOGLE_CERTS_URL));

  constructor(
    private readonly em: EntityManager,
    private readonly config: ConfigService,
    private readonly applications: ApplicationsService,
    private readonly tokenService: TokenService,
    private readonly audit: AuditService,
    private readonly metrics: MetricsService,
    @InjectRedis() private readonly redis: Redis,
  ) {}

  private cfg(key: string): string {
    const v = this.config.get<string>(key);
    if (!v) {
      throw new OAuthError(
        'temporarily_unavailable',
        'Google sign-in is not configured',
      );
    }
    return v;
  }

  /** Build the Google consent URL and persist the PKCE/state for the callback. */
  async buildAuthUrl(
    clientId: string,
    dashboardRedirect: string,
  ): Promise<string> {
    const app = await this.applications.findByClientId(clientId);
    if (!app) {
      throw OAuthError.invalidClient('Unknown client');
    }
    this.applications.assertGrantAllowed(app, GrantType.GOOGLE);
    if (!app.redirectUris.includes(dashboardRedirect)) {
      throw OAuthError.invalidRequest(
        'redirect_uri is not registered for this client',
      );
    }

    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');
    const nonce = randomBytes(16).toString('base64url');
    const state = uuid();

    await this.redis.set(
      `google:state:${state}`,
      JSON.stringify({
        applicationId: app.id,
        dashboardRedirect,
        codeVerifier,
        nonce,
      }),
      'EX',
      300,
    );

    const params = new URLSearchParams({
      client_id: this.cfg('GOOGLE_CLIENT_ID'),
      redirect_uri: this.cfg('GOOGLE_REDIRECT_URI'),
      response_type: 'code',
      scope: 'openid email profile',
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      access_type: 'online',
      prompt: 'select_account',
    });
    return `${GOOGLE_AUTH_URL}?${params.toString()}`;
  }

  /** Handle the Google callback: exchange code, verify, link, and issue tokens. */
  async handleCallback(
    code: string,
    state: string,
    meta: { ip?: string; userAgent?: string },
  ): Promise<{ tokens: TokenSet; dashboardRedirect: string }> {
    const raw = await this.redis.get(`google:state:${state}`);
    if (!raw) {
      throw OAuthError.invalidGrant('Invalid or expired state');
    }
    await this.redis.del(`google:state:${state}`);
    const stored = JSON.parse(raw) as GoogleState;

    const idToken = await this.exchangeCode(code, stored.codeVerifier);
    const claims = await this.verifyIdToken(idToken, stored.nonce);

    const app = await this.em.findOne(Application, {
      id: stored.applicationId,
    });
    if (!app) {
      throw OAuthError.invalidClient('Client no longer exists');
    }

    const user = await this.linkOrCreate(claims);
    const tokens = await this.tokenService.issueTokenSet(user, app, {
      amr: ['google'],
      grantType: 'google',
      scope: stored.scope,
      ip: meta.ip,
      userAgent: meta.userAgent,
    });

    await this.audit.record({
      eventType: 'login.success',
      userId: user.id,
      applicationId: app.id,
      ip: meta.ip,
      userAgent: meta.userAgent,
      metadata: { amr: ['google'] },
    });
    this.metrics.incLogin('google', 'success');
    return { tokens, dashboardRedirect: stored.dashboardRedirect };
  }

  private async exchangeCode(
    code: string,
    codeVerifier: string,
  ): Promise<string> {
    const res = await fetch(GOOGLE_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: this.cfg('GOOGLE_CLIENT_ID'),
        client_secret: this.cfg('GOOGLE_CLIENT_SECRET'),
        redirect_uri: this.cfg('GOOGLE_REDIRECT_URI'),
        grant_type: 'authorization_code',
        code_verifier: codeVerifier,
      }).toString(),
    });
    if (!res.ok) {
      this.logger.warn(`Google token exchange failed: ${res.status}`);
      throw OAuthError.invalidGrant('Google token exchange failed');
    }
    const body = (await res.json()) as { id_token?: string };
    if (!body.id_token) {
      throw OAuthError.invalidGrant('Google did not return an id_token');
    }
    return body.id_token;
  }

  private async verifyIdToken(
    idToken: string,
    nonce: string,
  ): Promise<{
    sub: string;
    email?: string;
    emailVerified: boolean;
    name?: string;
  }> {
    const { payload } = await jwtVerify(idToken, this.googleJwks, {
      issuer: GOOGLE_ISSUERS,
      audience: this.cfg('GOOGLE_CLIENT_ID'),
    });
    if (payload.nonce !== nonce) {
      throw OAuthError.invalidGrant('Google nonce mismatch');
    }
    return {
      sub: payload.sub as string,
      email: payload.email as string | undefined,
      emailVerified: payload.email_verified === true,
      name: payload.name as string | undefined,
    };
  }

  /** Find the user by Google subject, link by verified email, or create one. */
  private async linkOrCreate(claims: {
    sub: string;
    email?: string;
    emailVerified: boolean;
    name?: string;
  }): Promise<User> {
    const existing = await this.em.findOne(Identity, {
      provider: IdentityProvider.GOOGLE,
      providerSubject: claims.sub,
    });
    if (existing) {
      const user = await this.em.findOne(User, { id: existing.userId });
      if (user) return user;
    }

    let user = claims.email
      ? await this.em.findOne(User, { email: claims.email.toLowerCase() })
      : null;

    if (!user) {
      user = this.em.create(User, {
        email: claims.email?.toLowerCase(),
        emailVerified: claims.emailVerified,
        status: UserStatus.ACTIVE,
      } as unknown as User);
      this.em.persist(user);
      await this.em.flush();
    }

    const identity = this.em.create(Identity, {
      userId: user.id,
      provider: IdentityProvider.GOOGLE,
      providerSubject: claims.sub,
      email: claims.email,
      rawProfile: { name: claims.name },
    } as unknown as Identity);
    this.em.persist(identity);
    await this.em.flush();

    return user;
  }
}
