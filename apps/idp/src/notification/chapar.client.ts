import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';

/**
 * Thin client for the chapar notification gateway. Darboon implements NO SMS
 * provider itself — it generates and owns its OTP state, then hands the rendered
 * variables to chapar's `POST /notify` (channel=sms, template=otp-sms).
 * Authenticated with the plaintext API key in the `X-API-Key` header.
 */
@Injectable()
export class ChaparClient {
  private readonly logger = new Logger(ChaparClient.name);

  constructor(
    private readonly http: HttpService,
    private readonly config: ConfigService,
  ) {}

  private get baseUrl(): string {
    return this.config.getOrThrow<string>('CHAPAR_BASE_URL').replace(/\/$/, '');
  }

  private get headers(): Record<string, string> {
    return {
      'Content-Type': 'application/json',
      'X-API-Key': this.config.getOrThrow<string>('CHAPAR_API_KEY'),
    };
  }

  async sendSms(
    recipient: string,
    template: string,
    data: Record<string, unknown>,
  ): Promise<{ logId: string }> {
    const res = await firstValueFrom(
      this.http.post<{ logId: string }>(
        `${this.baseUrl}/notify`,
        { channel: 'sms', recipient, template, data },
        { headers: this.headers, timeout: 8000 },
      ),
    );
    this.logger.log(
      `chapar SMS queued logId=${res.data.logId} -> ${recipient}`,
    );
    return res.data;
  }

  async sendEmail(
    recipient: string,
    template: string,
    data: Record<string, unknown>,
    subject?: string,
  ): Promise<{ logId: string }> {
    const res = await firstValueFrom(
      this.http.post<{ logId: string }>(
        `${this.baseUrl}/notify`,
        { channel: 'email', recipient, template, subject, data },
        { headers: this.headers, timeout: 8000 },
      ),
    );
    this.logger.log(
      `chapar email queued logId=${res.data.logId} -> ${recipient}`,
    );
    return res.data;
  }
}
