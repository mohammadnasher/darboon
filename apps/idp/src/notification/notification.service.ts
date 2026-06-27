import { Injectable } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import {
  EMAIL_JOB,
  EmailJobData,
  NOTIFICATION_QUEUE,
  SMS_JOB,
  SmsJobData,
} from './notification.constants';

/** Enqueues notifications for the worker to deliver via chapar. */
@Injectable()
export class NotificationService {
  constructor(@InjectQueue(NOTIFICATION_QUEUE) private readonly queue: Queue) {}

  async sendSms(data: SmsJobData): Promise<void> {
    await this.queue.add(SMS_JOB, data);
  }

  async sendEmail(data: EmailJobData): Promise<void> {
    await this.queue.add(EMAIL_JOB, data);
  }
}
