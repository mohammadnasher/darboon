import {
  IsEmail,
  IsOptional,
  IsString,
  Matches,
  MinLength,
} from 'class-validator';

const E164 = /^\+?[1-9]\d{6,14}$/;

export class RegisterDto {
  @IsOptional() @IsEmail() email?: string;
  @IsOptional()
  @Matches(E164, { message: 'phone must be E.164' })
  phone?: string;
  @IsOptional() @IsString() username?: string;
  @IsString() @MinLength(8) password!: string;
}

export class ConfirmEmailDto {
  @IsString() token!: string;
}

export class RequestPhoneVerifyDto {
  @Matches(E164) phone!: string;
}

export class ConfirmPhoneDto {
  @Matches(E164) phone!: string;
  @IsString() code!: string;
}

export class ForgotPasswordDto {
  @IsString() identifier!: string;
}

export class ResetPasswordDto {
  @IsOptional() @IsString() token?: string;
  @IsOptional() @IsString() identifier?: string;
  @IsOptional() @IsString() code?: string;
  @IsString() @MinLength(8) newPassword!: string;
}
