export const NOTIFICATION_QUEUE = 'notifications';
export const SMS_JOB = 'send-sms';
export const EMAIL_JOB = 'send-email';

export interface SmsJobData {
  recipient: string;
  template: string;
  data: Record<string, unknown>;
}

export interface EmailJobData {
  recipient: string;
  template: string;
  subject?: string;
  data: Record<string, unknown>;
}
