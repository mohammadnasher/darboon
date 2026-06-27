import { Controller, Get, HttpCode, HttpStatus } from '@nestjs/common';
import { MikroORM } from '@mikro-orm/core';
import { InjectRedis } from '../redis/redis.module';
import Redis from 'ioredis';

/**
 * Public health endpoints for Docker HEALTHCHECK and Kubernetes probes.
 * `/health` is a cheap liveness check; `/health/ready` verifies DB + Redis.
 * Neither is behind an auth guard so probes can reach them unauthenticated.
 */
@Controller('health')
export class HealthController {
  constructor(
    private readonly orm: MikroORM,
    @InjectRedis() private readonly redis: Redis,
  ) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  check(): { status: 'ok'; timestamp: string } {
    return { status: 'ok', timestamp: new Date().toISOString() };
  }

  @Get('ready')
  async ready(): Promise<{ status: string; checks: Record<string, string> }> {
    const checks: Record<string, string> = {};
    let healthy = true;

    try {
      await this.orm.em.getConnection().execute('select 1');
      checks.database = 'ok';
    } catch {
      checks.database = 'down';
      healthy = false;
    }

    try {
      await this.redis.ping();
      checks.redis = 'ok';
    } catch {
      checks.redis = 'down';
      healthy = false;
    }

    return { status: healthy ? 'ok' : 'degraded', checks };
  }
}
