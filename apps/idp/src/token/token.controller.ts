import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { ApplicationsService } from '../applications/applications.service';
import { TokenService } from './token.service';
import { TokenVerifierService } from './token-verifier.service';
import {
  IntrospectionService,
  IntrospectionResponse,
} from './introspection.service';
import { IntrospectDto, RevokeDto } from './dto/revoke.dto';
import { ApiKeyGuard } from '../common/guards/api-key.guard';

/**
 * RFC 7009 revocation and RFC 7662 introspection. Revocation authenticates the
 * client; introspection authenticates the calling resource server via API key.
 */
@Controller('oauth')
export class TokenController {
  constructor(
    private readonly applications: ApplicationsService,
    private readonly tokenService: TokenService,
    private readonly verifier: TokenVerifierService,
    private readonly introspection: IntrospectionService,
  ) {}

  @Post('revoke')
  @HttpCode(HttpStatus.OK)
  async revoke(@Body() dto: RevokeDto): Promise<{ revoked: true }> {
    await this.applications.authenticateClient(
      dto.client_id,
      dto.client_secret,
    );

    if (dto.token_type_hint === 'access_token') {
      await this.revokeAccess(dto.token);
    } else {
      // Default + refresh_token hint: try refresh first, then access.
      await this.tokenService.revokeRefreshToken(dto.token);
      await this.revokeAccess(dto.token);
    }
    // RFC 7009: respond 200 regardless of whether the token existed.
    return { revoked: true };
  }

  private async revokeAccess(token: string): Promise<void> {
    const payload = await this.verifier.verify(token);
    if (payload?.jti && payload.exp) {
      await this.tokenService.revokeAccessToken(payload.jti, payload.exp);
    }
  }

  @Post('introspect')
  @HttpCode(HttpStatus.OK)
  @UseGuards(ApiKeyGuard)
  introspect(@Body() dto: IntrospectDto): Promise<IntrospectionResponse> {
    return this.introspection.introspect(dto.token);
  }
}
