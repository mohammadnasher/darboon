import { Injectable, Logger } from '@nestjs/common';
import { EntityManager } from '@mikro-orm/postgresql';
import { AuditLog } from '../entities';

export interface AuditEvent {
  eventType: string;
  userId?: string;
  applicationId?: string;
  actorId?: string;
  ip?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Append-only writer for security-relevant events (logins, token issue/revoke,
 * refresh reuse, role changes, key rotation). Failures to write an audit row
 * must never break the request, so writes are best-effort and logged.
 */
@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(private readonly em: EntityManager) {}

  async record(event: AuditEvent): Promise<void> {
    try {
      const log = this.em.create(AuditLog, {
        eventType: event.eventType,
        userId: event.userId,
        applicationId: event.applicationId,
        actorId: event.actorId,
        ip: event.ip,
        userAgent: event.userAgent,
        metadata: event.metadata,
      } as AuditLog);
      this.em.persist(log);
      await this.em.flush();
    } catch (err) {
      this.logger.error(
        `Failed to write audit log for "${event.eventType}"`,
        err instanceof Error ? err.stack : String(err),
      );
    }
  }
}
