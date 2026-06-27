import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createLocalJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { KeyService } from '../keys/key.service';
import { TokenService } from './token.service';

export interface VerifiedAccessToken extends JWTPayload {
  sub: string;
  client_id?: string;
  scope?: string;
  roles?: string[];
  permissions?: string[];
  amr?: string[];
}

/**
 * Verifies Darboon's own access tokens locally against the in-process JWKS,
 * then consults the revocation denylist. Used by /userinfo, /auth/logout, and
 * the introspection endpoint.
 */
@Injectable()
export class TokenVerifierService {
  constructor(
    private readonly config: ConfigService,
    private readonly keyService: KeyService,
    private readonly tokenService: TokenService,
  ) {}

  private get issuer(): string {
    return this.config.getOrThrow<string>('DARBOON_ISSUER');
  }

  /**
   * Verify signature, issuer, and expiry. Optionally pin the audience. Returns
   * null when the token is invalid, expired, or revoked.
   */
  async verify(
    token: string,
    audience?: string,
  ): Promise<VerifiedAccessToken | null> {
    try {
      const jwks = createLocalJWKSet(await this.keyService.getPublicJwks());
      const { payload } = await jwtVerify(token, jwks, {
        issuer: this.issuer,
        audience,
      });
      if (
        payload.jti &&
        (await this.tokenService.isAccessTokenRevoked(payload.jti))
      ) {
        return null;
      }
      return payload as VerifiedAccessToken;
    } catch {
      return null;
    }
  }
}
