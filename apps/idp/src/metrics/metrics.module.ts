import { Module } from '@nestjs/common';
import {
  makeCounterProvider,
  makeHistogramProvider,
} from '@willsoto/nestjs-prometheus';
import { MetricsService } from './metrics.service';

@Module({
  providers: [
    MetricsService,
    makeCounterProvider({
      name: 'darboon_logins_total',
      help: 'Total login attempts by method and result',
      labelNames: ['method', 'result'],
    }),
    makeCounterProvider({
      name: 'darboon_tokens_issued_total',
      help: 'Total access/refresh tokens issued by grant type',
      labelNames: ['grant_type'],
    }),
    makeCounterProvider({
      name: 'darboon_otp_sent_total',
      help: 'Total OTP codes dispatched by purpose',
      labelNames: ['purpose'],
    }),
    makeCounterProvider({
      name: 'darboon_introspection_total',
      help: 'Total token introspection calls by active result',
      labelNames: ['active'],
    }),
    makeHistogramProvider({
      name: 'darboon_token_issue_duration_seconds',
      help: 'Duration of token issuance in seconds',
      labelNames: ['grant_type'],
      buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1],
    }),
  ],
  exports: [MetricsService],
})
export class MetricsModule {}
