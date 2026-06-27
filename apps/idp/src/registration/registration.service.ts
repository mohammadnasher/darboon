import {
  BadRequestException,
  ConflictException,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EntityManager } from '@mikro-orm/postgresql';
import {
  OtpPurpose,
  RefreshToken,
  RefreshTokenStatus,
  User,
  UserStatus,
  VerificationPurpose,
  VerificationToken,
} from '../entities';
import { UsersService } from '../users/users.service';
import { CredentialsService } from '../credentials/credentials.service';
import { OtpService } from '../otp/otp.service';
import { NotificationService } from '../notification/notification.service';
import { AuditService } from '../audit/audit.service';
import { randomToken, sha256Hex } from '../common/crypto.util';
import { RegisterDto } from './dto/registration.dto';

/**
 * Self-service sign-up, email/phone verification, and password recovery. Email
 * verification uses a single-use link token; phone verification and password
 * reset use OTP codes dispatched through chapar.
 */
@Injectable()
export class RegistrationService {
  constructor(
    private readonly em: EntityManager,
    private readonly config: ConfigService,
    private readonly users: UsersService,
    private readonly credentials: CredentialsService,
    private readonly otp: OtpService,
    private readonly notifications: NotificationService,
    private readonly audit: AuditService,
  ) {}

  private get issuer(): string {
    return this.config.getOrThrow<string>('DARBOON_ISSUER').replace(/\/$/, '');
  }

  private get appName(): string {
    return this.config.get<string>('OTP_APP_NAME', 'Darboon');
  }

  async register(
    dto: RegisterDto,
  ): Promise<{ userId: string; status: string }> {
    if (!dto.email && !dto.phone) {
      throw new BadRequestException('email or phone is required');
    }
    if (dto.email && (await this.users.findByEmail(dto.email))) {
      throw new ConflictException('email already registered');
    }
    if (dto.phone && (await this.users.findByPhone(dto.phone))) {
      throw new ConflictException('phone already registered');
    }

    const user = this.em.create(User, {
      email: dto.email?.toLowerCase(),
      phone: dto.phone,
      username: dto.username,
      status: UserStatus.PENDING,
    } as unknown as User);
    this.em.persist(user);
    await this.em.flush();
    await this.credentials.setPassword(user.id, dto.password);

    if (dto.email) await this.sendEmailVerification(user);
    if (dto.phone)
      await this.sendPhoneOtp(user.id, dto.phone, OtpPurpose.PHONE_VERIFY);

    await this.audit.record({ eventType: 'user.registered', userId: user.id });
    return { userId: user.id, status: user.status };
  }

  // ── Email verification ──────────────────────────────────────────────────────
  private async sendEmailVerification(user: User): Promise<void> {
    const raw = randomToken(32);
    const token = this.em.create(VerificationToken, {
      userId: user.id,
      tokenHash: sha256Hex(raw),
      purpose: VerificationPurpose.EMAIL_VERIFY,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    } as unknown as VerificationToken);
    this.em.persist(token);
    await this.em.flush();

    await this.notifications.sendEmail({
      recipient: user.email!,
      template: 'welcome-email',
      subject: `Verify your ${this.appName} account`,
      data: {
        name: user.username ?? user.email,
        appName: this.appName,
        actionUrl: `${this.issuer}/verify/email/confirm?token=${raw}`,
      },
    });
  }

  async confirmEmail(rawToken: string): Promise<{ verified: true }> {
    const token = await this.em.findOne(VerificationToken, {
      tokenHash: sha256Hex(rawToken),
      purpose: VerificationPurpose.EMAIL_VERIFY,
      consumedAt: null,
    });
    if (!token || token.expiresAt.getTime() <= Date.now()) {
      throw new BadRequestException('Invalid or expired token');
    }
    const user = await this.users.findById(token.userId);
    if (!user) throw new BadRequestException('User not found');

    user.emailVerified = true;
    if (user.status === UserStatus.PENDING) user.status = UserStatus.ACTIVE;
    token.consumedAt = new Date();
    await this.em.flush();
    await this.audit.record({
      eventType: 'user.email_verified',
      userId: user.id,
    });
    return { verified: true };
  }

  // ── Phone verification ──────────────────────────────────────────────────────
  private async sendPhoneOtp(
    userId: string,
    phone: string,
    purpose: OtpPurpose,
  ): Promise<void> {
    const { code, expiresIn } = await this.otp.issue(phone, purpose, userId);
    await this.notifications.sendSms({
      recipient: phone,
      template: 'otp-sms',
      data: {
        appName: this.appName,
        otp: code,
        expiryMinutes: Math.round(expiresIn / 60),
      },
    });
  }

  async requestPhoneVerification(phone: string): Promise<{ sent: true }> {
    const user = await this.users.findByPhone(phone);
    if (user) {
      try {
        await this.sendPhoneOtp(user.id, phone, OtpPurpose.PHONE_VERIFY);
      } catch {
        // ignore resend throttle
      }
    }
    return { sent: true };
  }

  async confirmPhone(phone: string, code: string): Promise<{ verified: true }> {
    const result = await this.otp.verify(phone, OtpPurpose.PHONE_VERIFY, code);
    if (!result.ok) throw new BadRequestException('Invalid code');
    const user = await this.users.findByPhone(phone);
    if (!user) throw new BadRequestException('User not found');
    user.phoneVerified = true;
    if (user.status === UserStatus.PENDING) user.status = UserStatus.ACTIVE;
    await this.em.flush();
    await this.audit.record({
      eventType: 'user.phone_verified',
      userId: user.id,
    });
    return { verified: true };
  }

  // ── Password recovery ───────────────────────────────────────────────────────
  async forgotPassword(identifier: string): Promise<{ sent: true }> {
    const user = await this.users.findByIdentifier(identifier);
    if (user) {
      try {
        if (user.phone && user.phoneVerified) {
          await this.sendPhoneOtp(
            user.id,
            user.phone,
            OtpPurpose.PASSWORD_RESET,
          );
        } else if (user.email) {
          const raw = randomToken(32);
          const token = this.em.create(VerificationToken, {
            userId: user.id,
            tokenHash: sha256Hex(raw),
            purpose: VerificationPurpose.PASSWORD_RESET,
            expiresAt: new Date(Date.now() + 60 * 60 * 1000),
          } as unknown as VerificationToken);
          this.em.persist(token);
          await this.em.flush();
          await this.notifications.sendEmail({
            recipient: user.email,
            template: 'welcome-email',
            subject: `Reset your ${this.appName} password`,
            data: {
              name: user.email,
              appName: this.appName,
              actionUrl: `${this.issuer}/recovery/reset-password?token=${raw}`,
            },
          });
        }
      } catch {
        // ignore — uniform response below avoids enumeration
      }
    }
    return { sent: true };
  }

  async resetPassword(params: {
    token?: string;
    identifier?: string;
    code?: string;
    newPassword: string;
  }): Promise<{ reset: true }> {
    let userId: string | undefined;

    if (params.token) {
      const token = await this.em.findOne(VerificationToken, {
        tokenHash: sha256Hex(params.token),
        purpose: VerificationPurpose.PASSWORD_RESET,
        consumedAt: null,
      });
      if (!token || token.expiresAt.getTime() <= Date.now()) {
        throw new BadRequestException('Invalid or expired token');
      }
      token.consumedAt = new Date();
      userId = token.userId;
    } else if (params.identifier && params.code) {
      const user = await this.users.findByIdentifier(params.identifier);
      if (!user?.phone) throw new BadRequestException('Invalid reset request');
      const result = await this.otp.verify(
        user.phone,
        OtpPurpose.PASSWORD_RESET,
        params.code,
      );
      if (!result.ok) throw new BadRequestException('Invalid code');
      userId = user.id;
    } else {
      throw new BadRequestException('token or identifier+code is required');
    }

    await this.credentials.setPassword(userId, params.newPassword);
    await this.revokeAllSessions(userId);
    await this.em.flush();
    await this.audit.record({ eventType: 'user.password_reset', userId });
    return { reset: true };
  }

  /** Invalidate every refresh token for a user after a credential change. */
  private async revokeAllSessions(userId: string): Promise<void> {
    const tokens = await this.em.find(RefreshToken, {
      userId,
      status: { $in: [RefreshTokenStatus.ACTIVE, RefreshTokenStatus.ROTATED] },
    });
    tokens.forEach((t) => (t.status = RefreshTokenStatus.REVOKED));
  }
}
