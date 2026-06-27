import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { EntityManager } from '@mikro-orm/postgresql';
import { v4 as uuid } from 'uuid';
import {
  Application,
  ApplicationStatus,
  AuditLog,
  GrantType,
  Permission,
  RefreshToken,
  RefreshTokenStatus,
  Role,
  RolePermission,
  User,
  UserApplicationRole,
  UserStatus,
} from '../entities';
import { randomToken, sha256Hex } from '../common/crypto.util';
import { RbacService } from '../rbac/rbac.service';
import {
  AssignRoleDto,
  CreateApplicationDto,
  CreatePermissionDto,
  CreateRoleDto,
  SetRolePermissionsDto,
  UpdateApplicationDto,
} from './dto/admin.dto';

/** Backing service for the admin RBAC + client-management API. */
@Injectable()
export class AdminService {
  constructor(
    private readonly em: EntityManager,
    private readonly rbac: RbacService,
  ) {}

  // ── Applications ────────────────────────────────────────────────────────────
  listApplications(): Promise<Application[]> {
    return this.em.find(Application, {}, { orderBy: { createdAt: 'desc' } });
  }

  async getApplication(id: string): Promise<Application> {
    const app = await this.em.findOne(Application, { id });
    if (!app) throw new NotFoundException('Application not found');
    return app;
  }

  async createApplication(
    dto: CreateApplicationDto,
  ): Promise<{ application: Application; clientSecret?: string }> {
    const clientId = dto.clientId ?? `app_${randomToken(8)}`;
    if (await this.em.findOne(Application, { clientId })) {
      throw new ConflictException('clientId already exists');
    }
    if (await this.em.findOne(Application, { audience: dto.audience })) {
      throw new ConflictException('audience already exists');
    }

    let clientSecret: string | undefined;
    let clientSecretHash: string | undefined;
    if (dto.confidential) {
      clientSecret = randomToken(32);
      clientSecretHash = sha256Hex(clientSecret);
    }

    const app = this.em.create(Application, {
      clientId,
      clientSecretHash,
      name: dto.name,
      audience: dto.audience,
      redirectUris: dto.redirectUris ?? [],
      allowedGrantTypes: dto.allowedGrantTypes ?? [
        GrantType.PASSWORD,
        GrantType.REFRESH_TOKEN,
      ],
      requirePkce: dto.requirePkce ?? true,
      isFirstParty: !dto.confidential,
      status: ApplicationStatus.ACTIVE,
    } as unknown as Application);
    this.em.persist(app);
    await this.em.flush();
    return { application: app, clientSecret };
  }

  async updateApplication(
    id: string,
    dto: UpdateApplicationDto,
  ): Promise<Application> {
    const app = await this.getApplication(id);
    if (dto.name !== undefined) app.name = dto.name;
    if (dto.redirectUris !== undefined) app.redirectUris = dto.redirectUris;
    if (dto.allowedGrantTypes !== undefined)
      app.allowedGrantTypes = dto.allowedGrantTypes;
    if (dto.status !== undefined) app.status = dto.status as ApplicationStatus;
    await this.em.flush();
    return app;
  }

  async deleteApplication(id: string): Promise<void> {
    const app = await this.getApplication(id);
    this.em.remove(app);
    await this.em.flush();
  }

  async rotateSecret(id: string): Promise<{ clientSecret: string }> {
    const app = await this.getApplication(id);
    const clientSecret = randomToken(32);
    app.clientSecretHash = sha256Hex(clientSecret);
    app.isFirstParty = false;
    await this.em.flush();
    return { clientSecret };
  }

  // ── Roles & permissions ─────────────────────────────────────────────────────
  listRoles(applicationId: string): Promise<Role[]> {
    return this.em.find(Role, { applicationId });
  }

  async createRole(applicationId: string, dto: CreateRoleDto): Promise<Role> {
    await this.getApplication(applicationId);
    const role = this.em.create(Role, {
      applicationId,
      name: dto.name,
      description: dto.description,
      isDefault: dto.isDefault ?? false,
    } as unknown as Role);
    this.em.persist(role);
    await this.em.flush();
    return role;
  }

  async deleteRole(roleId: string): Promise<void> {
    const role = await this.em.findOne(Role, { id: roleId });
    if (!role) throw new NotFoundException('Role not found');
    this.em.remove(role);
    await this.em.flush();
  }

  listPermissions(applicationId: string): Promise<Permission[]> {
    return this.em.find(Permission, { applicationId });
  }

  async createPermission(
    applicationId: string,
    dto: CreatePermissionDto,
  ): Promise<Permission> {
    await this.getApplication(applicationId);
    const permission = this.em.create(Permission, {
      applicationId,
      name: dto.name,
      description: dto.description,
    } as unknown as Permission);
    this.em.persist(permission);
    await this.em.flush();
    return permission;
  }

  async setRolePermissions(
    roleId: string,
    dto: SetRolePermissionsDto,
  ): Promise<{ roleId: string; permissionIds: string[] }> {
    const role = await this.em.findOne(Role, { id: roleId });
    if (!role) throw new NotFoundException('Role not found');
    const existing = await this.em.find(RolePermission, { roleId });
    existing.forEach((rp) => this.em.remove(rp));
    for (const permissionId of dto.permissionIds) {
      this.em.persist(
        this.em.create(RolePermission, {
          roleId,
          permissionId,
        }),
      );
    }
    await this.em.flush();
    await this.invalidateRoleHolders(roleId);
    return { roleId, permissionIds: dto.permissionIds };
  }

  // ── Users & assignments ─────────────────────────────────────────────────────
  listUsers(query?: string): Promise<User[]> {
    const where = query
      ? {
          $or: [
            { email: { $ilike: `%${query}%` } },
            { username: { $ilike: `%${query}%` } },
            { phone: { $ilike: `%${query}%` } },
          ],
        }
      : {};
    return this.em.find(User, where, {
      orderBy: { createdAt: 'desc' },
      limit: 100,
    });
  }

  async getUser(id: string): Promise<User> {
    const user = await this.em.findOne(User, { id });
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async updateUserStatus(id: string, status: UserStatus): Promise<User> {
    const user = await this.getUser(id);
    user.status = status;
    if (status === UserStatus.ACTIVE) {
      user.failedLoginCount = 0;
      user.lockedUntil = undefined;
    }
    await this.em.flush();
    return user;
  }

  listUserRoles(userId: string): Promise<UserApplicationRole[]> {
    return this.em.find(UserApplicationRole, { userId });
  }

  async assignRole(
    userId: string,
    dto: AssignRoleDto,
    actorId?: string,
  ): Promise<UserApplicationRole> {
    await this.getUser(userId);
    const existing = await this.em.findOne(UserApplicationRole, {
      userId,
      applicationId: dto.applicationId,
      roleId: dto.roleId,
    });
    if (existing) return existing;

    const assignment = this.em.create(UserApplicationRole, {
      id: uuid(),
      userId,
      applicationId: dto.applicationId,
      roleId: dto.roleId,
      grantedBy: actorId,
    } as unknown as UserApplicationRole);
    this.em.persist(assignment);
    await this.em.flush();
    await this.rbac.invalidateUser(userId);
    return assignment;
  }

  async revokeRole(userId: string, assignmentId: string): Promise<void> {
    const assignment = await this.em.findOne(UserApplicationRole, {
      id: assignmentId,
      userId,
    });
    if (!assignment) throw new NotFoundException('Assignment not found');
    this.em.remove(assignment);
    await this.em.flush();
    await this.rbac.invalidateUser(userId);
  }

  // ── Sessions ────────────────────────────────────────────────────────────────
  listSessions(userId: string): Promise<RefreshToken[]> {
    return this.em.find(
      RefreshToken,
      { userId, status: RefreshTokenStatus.ACTIVE },
      { orderBy: { createdAt: 'desc' } },
    );
  }

  async revokeAllSessions(userId: string): Promise<{ revoked: number }> {
    const tokens = await this.em.find(RefreshToken, {
      userId,
      status: { $in: [RefreshTokenStatus.ACTIVE, RefreshTokenStatus.ROTATED] },
    });
    tokens.forEach((t) => (t.status = RefreshTokenStatus.REVOKED));
    await this.em.flush();
    return { revoked: tokens.length };
  }

  // ── Audit ───────────────────────────────────────────────────────────────────
  queryAudit(filter: {
    eventType?: string;
    userId?: string;
    limit?: number;
  }): Promise<AuditLog[]> {
    const where: Record<string, unknown> = {};
    if (filter.eventType) where.eventType = filter.eventType;
    if (filter.userId) where.userId = filter.userId;
    return this.em.find(AuditLog, where, {
      orderBy: { createdAt: 'desc' },
      limit: Math.min(filter.limit ?? 100, 500),
    });
  }

  private async invalidateRoleHolders(roleId: string): Promise<void> {
    const holders = await this.em.find(UserApplicationRole, { roleId });
    await Promise.all(
      [...new Set(holders.map((h) => h.userId))].map((u) =>
        this.rbac.invalidateUser(u),
      ),
    );
  }
}
