import { NestFactory } from '@nestjs/core';
import { Logger, ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MikroORM } from '@mikro-orm/core';
import helmet from 'helmet';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { AppModule } from './app.module';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { LoggingInterceptor } from './common/interceptors/logging.interceptor';
import { getRole } from './config/runtime';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    logger: ['log', 'warn', 'error'],
  });

  Logger.log(`Starting Darboon IDP in "${getRole()}" role`, 'Bootstrap');

  const config = app.get(ConfigService);

  // Trust the first proxy hop so client IPs (audit/rate-limit) are accurate.
  app.set('trust proxy', 1);

  // Apply pending migrations from a single instance (the API) to avoid races.
  if (config.get<boolean>('RUN_MIGRATIONS', false)) {
    const orm = app.get(MikroORM);
    await orm.migrator.up();
    Logger.log('Database migrations applied', 'Bootstrap');
  }

  app.use(helmet());

  const origins = config.get<string>('CORS_ALLOWED_ORIGINS', '*');
  app.enableCors({
    origin: origins === '*' ? true : origins.split(',').map((o) => o.trim()),
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  app.useGlobalFilters(new HttpExceptionFilter());
  app.useGlobalInterceptors(new LoggingInterceptor());

  const port = config.get<number>('PORT', 3000);
  await app.listen(port);
  Logger.log(`Darboon IDP listening on :${port}`, 'Bootstrap');
}

void bootstrap();
