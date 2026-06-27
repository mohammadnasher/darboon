import { Injectable } from '@nestjs/common';
import { InjectMetric } from '@willsoto/nestjs-prometheus';
import { Counter, Histogram } from 'prom-client';

@Injectable()
export class MetricsService {
  constructor(
    @InjectMetric('darboon_logins_total')
    private readonly loginsCounter: Counter<string>,

    @InjectMetric('darboon_tokens_issued_total')
    private readonly tokensIssuedCounter: Counter<string>,

    @InjectMetric('darboon_otp_sent_total')
    private readonly otpSentCounter: Counter<string>,

    @InjectMetric('darboon_introspection_total')
    private readonly introspectionCounter: Counter<string>,

    @InjectMetric('darboon_token_issue_duration_seconds')
    private readonly issueHistogram: Histogram<string>,
  ) {}

  /** result: 'success' | 'failure' | 'mfa_required'; method: 'password' | 'otp' | 'google'. */
  incLogin(method: string, result: string): void {
    this.loginsCounter.inc({ method, result });
  }

  incTokenIssued(grantType: string): void {
    this.tokensIssuedCounter.inc({ grant_type: grantType });
  }

  incOtpSent(purpose: string): void {
    this.otpSentCounter.inc({ purpose });
  }

  incIntrospection(active: boolean): void {
    this.introspectionCounter.inc({ active: String(active) });
  }

  startIssueTimer(grantType: string): () => void {
    return this.issueHistogram.startTimer({ grant_type: grantType });
  }
}
