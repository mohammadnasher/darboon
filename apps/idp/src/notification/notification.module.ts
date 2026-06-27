import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { BullModule } from '@nestjs/bullmq';
import { ChaparClient } from './chapar.client';
import { NotificationService } from './notification.service';
import { NotificationProcessor } from './notification.processor';
import { NOTIFICATION_QUEUE } from './notification.constants';
import { runsWorker } from '../config/runtime';

@Module({
  imports: [
    HttpModule,
    BullModule.registerQueue({
      name: NOTIFICATION_QUEUE,
      defaultJobOptions: {
        attempts: 5,
        backoff: { type: 'exponential', delay: 2000 },
        removeOnComplete: { count: 1000 },
        removeOnFail: false,
      },
    }),
  ],
  // Only worker-capable roles consume the queue; the API just enqueues.
  providers: [
    NotificationService,
    ...(runsWorker() ? [ChaparClient, NotificationProcessor] : []),
  ],
  exports: [NotificationService],
})
export class NotificationModule {}
