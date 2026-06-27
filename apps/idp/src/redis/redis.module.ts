import { Global, Inject, Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

export const REDIS_CLIENT = 'REDIS_CLIENT';

/** Param/property decorator to inject the shared ioredis client. */
export const InjectRedis = () => Inject(REDIS_CLIENT);

/**
 * A single shared ioredis connection, reused by the health probe, the RBAC
 * claims cache, and the throttler storage. BullMQ manages its own connection.
 */
@Global()
@Module({
  providers: [
    {
      provide: REDIS_CLIENT,
      inject: [ConfigService],
      useFactory: (config: ConfigService): Redis => {
        return new Redis(config.getOrThrow<string>('REDIS_URL'), {
          maxRetriesPerRequest: null,
          lazyConnect: false,
        });
      },
    },
  ],
  exports: [REDIS_CLIENT],
})
export class RedisModule {}
