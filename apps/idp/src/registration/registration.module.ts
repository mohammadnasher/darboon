import { Module } from '@nestjs/common';
import { RegistrationService } from './registration.service';
import { RegistrationController } from './registration.controller';
import { UsersModule } from '../users/users.module';
import { CredentialsModule } from '../credentials/credentials.module';
import { OtpModule } from '../otp/otp.module';
import { NotificationModule } from '../notification/notification.module';

@Module({
  imports: [UsersModule, CredentialsModule, OtpModule, NotificationModule],
  controllers: [RegistrationController],
  providers: [RegistrationService],
})
export class RegistrationModule {}
