import { Controller, Get } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Throttle } from '@nestjs/throttler';
import type { JWK } from 'jose';
import { KeyService } from '../keys/key.service';

/**
 * OIDC discovery + JWKS. Both are public and cacheable so downstream services
 * (and the verifier SDK) can bootstrap verification without credentials.
 */
@Controller()
export class OidcController {
  constructor(
    private readonly config: ConfigService,
    private readonly keyService: KeyService,
  ) {}

  private get issuer(): string {
    return this.config.getOrThrow<string>('DARBOON_ISSUER');
  }

  @Get('.well-known/openid-configuration')
  @Throttle({ default: { limit: 60, ttl: 60000 } })
  discovery(): Record<string, unknown> {
    const issuer = this.issuer.replace(/\/$/, '');
    return {
      issuer,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      token_endpoint: `${issuer}/oauth/token`,
      userinfo_endpoint: `${issuer}/userinfo`,
      revocation_endpoint: `${issuer}/oauth/revoke`,
      introspection_endpoint: `${issuer}/oauth/introspect`,
      response_types_supported: ['token'],
      grant_types_supported: [
        'password',
        'refresh_token',
        'urn:darboon:otp',
        'urn:darboon:google',
      ],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: [
        this.config.get<string>('JWT_ALG', 'ES256'),
      ],
      scopes_supported: ['openid', 'profile', 'email', 'phone'],
      claims_supported: [
        'sub',
        'aud',
        'iss',
        'exp',
        'iat',
        'jti',
        'roles',
        'permissions',
        'amr',
        'email',
        'email_verified',
        'phone_number',
      ],
    };
  }

  @Get('.well-known/jwks.json')
  @Throttle({ default: { limit: 120, ttl: 60000 } })
  async jwks(): Promise<{ keys: JWK[] }> {
    return this.keyService.getPublicJwks();
  }
}
