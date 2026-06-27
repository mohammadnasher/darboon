import { Injectable } from '@nestjs/common';
import { TokenVerifierService } from './token-verifier.service';
import { MetricsService } from '../metrics/metrics.service';

export interface IntrospectionResponse {
  active: boolean;
  sub?: string;
  aud?: string | string[];
  iss?: string;
  exp?: number;
  iat?: number;
  jti?: string;
  client_id?: string;
  scope?: string;
  roles?: string[];
  permissions?: string[];
  token_type?: string;
}

/**
 * RFC 7662 token introspection. Lets high-security resource servers verify a
 * token's live status (including revocation) instead of relying solely on local
 * JWKS verification.
 */
@Injectable()
export class IntrospectionService {
  constructor(
    private readonly verifier: TokenVerifierService,
    private readonly metrics: MetricsService,
  ) {}

  async introspect(token: string): Promise<IntrospectionResponse> {
    const payload = await this.verifier.verify(token);
    if (!payload) {
      this.metrics.incIntrospection(false);
      return { active: false };
    }
    this.metrics.incIntrospection(true);
    return {
      active: true,
      sub: payload.sub,
      aud: payload.aud,
      iss: payload.iss,
      exp: payload.exp,
      iat: payload.iat,
      jti: payload.jti,
      client_id: payload.client_id,
      scope: payload.scope,
      roles: payload.roles,
      permissions: payload.permissions,
      token_type: 'Bearer',
    };
  }
}
