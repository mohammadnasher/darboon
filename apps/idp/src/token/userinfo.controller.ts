import {
  Controller,
  Get,
  NotFoundException,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import { AccessTokenGuard } from './access-token.guard';
import { UsersService } from '../users/users.service';
import { VerifiedAccessToken } from './token-verifier.service';

/** OIDC userinfo endpoint. Returns the standard claims for the bearer subject. */
@Controller('userinfo')
@UseGuards(AccessTokenGuard)
export class UserinfoController {
  constructor(private readonly users: UsersService) {}

  @Get()
  async userinfo(@Req() req: Request): Promise<Record<string, unknown>> {
    const payload = (req as Request & { user: VerifiedAccessToken }).user;
    const user = await this.users.findById(payload.sub);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return {
      sub: user.id,
      email: user.email,
      email_verified: user.emailVerified,
      phone_number: user.phone,
      phone_number_verified: user.phoneVerified,
      preferred_username: user.username,
    };
  }
}
