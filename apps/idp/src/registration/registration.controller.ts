import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { RegistrationService } from './registration.service';
import {
  ConfirmEmailDto,
  ConfirmPhoneDto,
  ForgotPasswordDto,
  RegisterDto,
  RequestPhoneVerifyDto,
  ResetPasswordDto,
} from './dto/registration.dto';

@Controller()
export class RegistrationController {
  constructor(private readonly registration: RegistrationService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  register(@Body() dto: RegisterDto) {
    return this.registration.register(dto);
  }

  @Post('verify/email/confirm')
  @HttpCode(HttpStatus.OK)
  confirmEmail(@Body() dto: ConfirmEmailDto) {
    return this.registration.confirmEmail(dto.token);
  }

  // Convenience GET so the email link is directly clickable.
  @Get('verify/email/confirm')
  confirmEmailGet(@Query('token') token: string) {
    return this.registration.confirmEmail(token);
  }

  @Post('verify/phone/request')
  @HttpCode(HttpStatus.ACCEPTED)
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  requestPhone(@Body() dto: RequestPhoneVerifyDto) {
    return this.registration.requestPhoneVerification(dto.phone);
  }

  @Post('verify/phone/confirm')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  confirmPhone(@Body() dto: ConfirmPhoneDto) {
    return this.registration.confirmPhone(dto.phone, dto.code);
  }

  @Post('recovery/forgot-password')
  @HttpCode(HttpStatus.ACCEPTED)
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.registration.forgotPassword(dto.identifier);
  }

  @Post('recovery/reset-password')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  resetPassword(@Body() dto: ResetPasswordDto) {
    return this.registration.resetPassword({
      token: dto.token,
      identifier: dto.identifier,
      code: dto.code,
      newPassword: dto.newPassword,
    });
  }
}
