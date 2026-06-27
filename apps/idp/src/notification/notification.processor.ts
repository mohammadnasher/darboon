import { Logger } from '@nestjs/common';
import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { ChaparClient } from './chapar.client';
import {
  EMAIL_JOB,
  EmailJobData,
  NOTIFICATION_QUEUE,
  SMS_JOB,
  SmsJobData,
} from './notification.constants';

/**
 * Worker-side consumer that delivers queued notifications via chapar. Retries
 * (with backoff) are handled by BullMQ job options; chapar has its own internal
 * retry + audit, so delivery here is fire-and-forget once accepted.
 */
@Processor(NOTIFICATION_QUEUE)
export class NotificationProcessor extends WorkerHost {
  private readonly logger = new Logger(NotificationProcessor.name);

  constructor(private readonly chapar: ChaparClient) {
    super();
  }

  async process(job: Job): Promise<void> {
    if (job.name === SMS_JOB) {
      const { recipient, template, data } = job.data as SmsJobData;
      await this.chapar.sendSms(recipient, template, data);
    } else if (job.name === EMAIL_JOB) {
      const { recipient, template, data, subject } = job.data as EmailJobData;
      await this.chapar.sendEmail(recipient, template, data, subject);
    } else {
      this.logger.warn(`Unknown notification job "${job.name}"`);
    }
  }
}
