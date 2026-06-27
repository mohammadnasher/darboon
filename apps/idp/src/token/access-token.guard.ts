import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { TokenVerifierService } from './token-verifier.service';

/**
 * Guards Darboon's own first-party endpoints (e.g. /userinfo, /auth/logout) by
 * verifying the bearer access token it issued. Attaches the verified payload to
 * `request.user`.
 */
@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(private readonly verifier: TokenVerifierService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const header = request.headers.authorization;
    if (!header?.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing bearer token');
    }
    const payload = await this.verifier.verify(header.slice(7));
    if (!payload) {
      throw new UnauthorizedException('Invalid or expired token');
    }
    (request as Request & { user?: unknown }).user = payload;
    return true;
  }
}
