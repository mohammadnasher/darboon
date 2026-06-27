import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { ThrottlerStorageRedisService } from '@nest-lab/throttler-storage-redis';
import { BullModule } from '@nestjs/bullmq';
import { MikroOrmModule } from '@mikro-orm/nestjs';
import { PrometheusModule } from '@willsoto/nestjs-prometheus';
import { validationSchema } from './config/app.config';
import { mikroOrmConfig } from './config/database.config';
import { RedisModule } from './redis/redis.module';
import { AuditModule } from './audit/audit.module';
import { MetricsModule } from './metrics/metrics.module';
import { HealthModule } from './health/health.module';
import { KeysModule } from './keys/keys.module';
import { TokenModule } from './token/token.module';
import { NotificationModule } from './notification/notification.module';
import { OtpModule } from './otp/otp.module';
import { AuthModule } from './auth/auth.module';
import { GoogleModule } from './google/google.module';
import { AdminModule } from './admin/admin.module';
import { RegistrationModule } from './registration/registration.module';
import { BootstrapModule } from './bootstrap/bootstrap.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, validationSchema }),
    ThrottlerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        throttlers: [
          {
            ttl: config.get<number>('THROTTLE_TTL', 60) * 1000,
            limit: config.get<number>('THROTTLE_LIMIT', 100),
          },
        ],
        // Distributed counters so limits hold across replicas.
        storage: new ThrottlerStorageRedisService(
          config.getOrThrow<string>('REDIS_URL'),
        ),
      }),
    }),
    BullModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        connection: { url: config.getOrThrow<string>('REDIS_URL') },
      }),
    }),
    MikroOrmModule.forRootAsync({ useFactory: mikroOrmConfig }),
    PrometheusModule.register({
      path: '/metrics',
      defaultMetrics: { enabled: true },
    }),
    RedisModule,
    AuditModule,
    MetricsModule,
    HealthModule,
    KeysModule,
    TokenModule,
    NotificationModule,
    OtpModule,
    AuthModule,
    GoogleModule,
    AdminModule,
    RegistrationModule,
    BootstrapModule,
  ],
  providers: [{ provide: APP_GUARD, useClass: ThrottlerGuard }],
})
export class AppModule {}
