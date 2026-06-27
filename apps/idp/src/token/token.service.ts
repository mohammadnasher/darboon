import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EntityManager } from '@mikro-orm/postgresql';
import { SignJWT } from 'jose';
import { v4 as uuid } from 'uuid';
import Redis from 'ioredis';
import {
  Application,
  RefreshToken,
  RefreshTokenStatus,
  User,
} from '../entities';
import { KeyService } from '../keys/key.service';
import { RbacService } from '../rbac/rbac.service';
import { AuditService } from '../audit/audit.service';
import { MetricsService } from '../metrics/metrics.service';
import { randomToken, sha256Hex } from '../common/crypto.util';
import { OAuthError } from '../common/oauth-error';
import { InjectRedis } from '../redis/redis.module';

export interface IssueContext {
  scope?: string;
  amr: string[]; // authentication methods, e.g. ['pwd'] or ['pwd','otp']
  grantType: string;
  ip?: string;
  userAgent?: string;
  familyId?: string; // set when rotating within an existing family
  parentId?: string;
}

export interface TokenSet {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token: string;
  scope?: string;
  id_token?: string;
}

/**
 * Mints access (JWT) + refresh (opaque, rotating) token pairs and enforces
 * refresh-token rotation with family-wide reuse detection.
 */
@Injectable()
export class TokenService {
  private readonly logger = new Logger(TokenService.name);

  constructor(
    private readonly em: EntityManager,
    private readonly config: ConfigService,
    private readonly keyService: KeyService,
    private readonly rbac: RbacService,
    private readonly audit: AuditService,
    private readonly metrics: MetricsService,
    @InjectRedis() private readonly redis: Redis,
  ) {}

  private get issuer(): string {
    return this.config.getOrThrow<string>('DARBOON_ISSUER');
  }

  /** Build a signed access-token JWT scoped to one application. */
  private async signAccessToken(
    user: User,
    app: Application,
    ctx: IssueContext,
  ): Promise<{ token: string; jti: string; expiresIn: number }> {
    const { kid, alg, privateKey } =
      await this.keyService.getActiveSigningKey();
    const { roles, permissions } = await this.rbac.resolve(user.id, app.id);
    const ttl = app.accessTokenTtlSeconds;
    const jti = uuid();

    const token = await new SignJWT({
      client_id: app.clientId,
      scope: ctx.scope,
      roles,
      permissions,
      amr: ctx.amr,
      token_use: 'access',
    })
      .setProtectedHeader({ alg, kid, typ: 'at+jwt' })
      .setIssuer(this.issuer)
      .setSubject(user.id)
      .setAudience(app.audience)
      .setIssuedAt()
      .setNotBefore('0s')
      .setExpirationTime(`${ttl}s`)
      .setJti(jti)
      .sign(privateKey);

    return { token, jti, expiresIn: ttl };
  }

  /** OIDC ID token, issued only when the `openid` scope is requested. */
  private async signIdToken(user: User, app: Application): Promise<string> {
    const { kid, alg, privateKey } =
      await this.keyService.getActiveSigningKey();
    return new SignJWT({
      email: user.email,
      email_verified: user.emailVerified,
      phone_number: user.phone,
      phone_number_verified: user.phoneVerified,
    })
      .setProtectedHeader({ alg, kid })
      .setIssuer(this.issuer)
      .setSubject(user.id)
      .setAudience(app.clientId)
      .setIssuedAt()
      .setExpirationTime(`${app.accessTokenTtlSeconds}s`)
      .sign(privateKey);
  }

  private async createRefreshToken(
    user: User,
    app: Application,
    ctx: IssueContext,
  ): Promise<string> {
    const raw = randomToken(32);
    const entity = this.em.create(RefreshToken, {
      userId: user.id,
      applicationId: app.id,
      tokenHash: sha256Hex(raw),
      familyId: ctx.familyId ?? uuid(),
      parentId: ctx.parentId,
      status: RefreshTokenStatus.ACTIVE,
      expiresAt: new Date(Date.now() + app.refreshTokenTtlSeconds * 1000),
      userAgent: ctx.userAgent,
      ip: ctx.ip,
    } as RefreshToken);
    this.em.persist(entity);
    await this.em.flush();
    return `${entity.id}.${raw}`; // id prefix lets us look up without scanning
  }

  /** Issue a fresh access + refresh pair (new family) after a successful login. */
  async issueTokenSet(
    user: User,
    app: Application,
    ctx: IssueContext,
  ): Promise<TokenSet> {
    const stop = this.metrics.startIssueTimer(ctx.grantType);
    const { token, expiresIn } = await this.signAccessToken(user, app, ctx);
    const refresh = await this.createRefreshToken(user, app, ctx);
    const scopes = (ctx.scope ?? '').split(' ').filter(Boolean);
    const idToken = scopes.includes('openid')
      ? await this.signIdToken(user, app)
      : undefined;

    this.metrics.incTokenIssued(ctx.grantType);
    stop();

    return {
      access_token: token,
      token_type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: refresh,
      scope: ctx.scope,
      id_token: idToken,
    };
  }

  /**
   * Exchange a refresh token for a new pair, rotating within the same family.
   * If the presented token is not active (already rotated/revoked), this is
   * treated as reuse: the entire family is revoked and the request denied.
   */
  async refresh(
    rawRefreshToken: string,
    app: Application,
    ctx: Omit<IssueContext, 'amr' | 'familyId' | 'parentId'>,
  ): Promise<TokenSet> {
    const [id, secret] = rawRefreshToken.split('.');
    if (!id || !secret) {
      throw OAuthError.invalidGrant('Malformed refresh token');
    }
    const record = await this.em.findOne(RefreshToken, { id });
    if (!record || record.tokenHash !== sha256Hex(secret)) {
      throw OAuthError.invalidGrant('Unknown refresh token');
    }
    if (record.applicationId !== app.id) {
      throw OAuthError.invalidGrant(
        'Refresh token was issued to another client',
      );
    }

    if (record.status !== RefreshTokenStatus.ACTIVE) {
      // Reuse of a consumed/revoked token — revoke the whole lineage.
      await this.revokeFamily(record.familyId, RefreshTokenStatus.REUSED);
      await this.audit.record({
        eventType: 'refresh_token.reuse_detected',
        userId: record.userId,
        applicationId: record.applicationId,
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: { familyId: record.familyId },
      });
      this.logger.warn(
        `Refresh token reuse detected for family ${record.familyId}; family revoked`,
      );
      throw OAuthError.invalidGrant('Refresh token has already been used');
    }

    if (record.expiresAt.getTime() <= Date.now()) {
      throw OAuthError.invalidGrant('Refresh token has expired');
    }

    const user = await this.em.findOne(User, { id: record.userId });
    if (!user) {
      throw OAuthError.invalidGrant('User no longer exists');
    }

    // Rotate: mark the presented token consumed, mint a successor in the family.
    record.status = RefreshTokenStatus.ROTATED;
    record.lastUsedAt = new Date();
    await this.em.flush();

    return this.issueTokenSet(user, app, {
      ...ctx,
      amr: ['refresh'],
      grantType: 'refresh_token',
      familyId: record.familyId,
      parentId: record.id,
    });
  }

  /** Revoke every token in a family (logout-all / reuse response). */
  async revokeFamily(
    familyId: string,
    status: RefreshTokenStatus = RefreshTokenStatus.REVOKED,
  ): Promise<void> {
    const tokens = await this.em.find(RefreshToken, {
      familyId,
      status: {
        $in: [RefreshTokenStatus.ACTIVE, RefreshTokenStatus.ROTATED],
      },
    });
    for (const t of tokens) {
      t.status = status;
    }
    await this.em.flush();
  }

  /** Revoke a single refresh token (and its family) given the raw value. */
  async revokeRefreshToken(rawRefreshToken: string): Promise<void> {
    const [id, secret] = rawRefreshToken.split('.');
    if (!id || !secret) return;
    const record = await this.em.findOne(RefreshToken, { id });
    if (!record || record.tokenHash !== sha256Hex(secret)) return;
    await this.revokeFamily(record.familyId, RefreshTokenStatus.REVOKED);
  }

  /** Add an access-token jti to the revocation denylist until it would expire. */
  async revokeAccessToken(jti: string, expSeconds: number): Promise<void> {
    const ttl = Math.max(1, expSeconds - Math.floor(Date.now() / 1000));
    await this.redis.set(`revoked:at:${jti}`, '1', 'EX', ttl);
  }

  async isAccessTokenRevoked(jti: string): Promise<boolean> {
    return (await this.redis.exists(`revoked:at:${jti}`)) === 1;
  }
}
