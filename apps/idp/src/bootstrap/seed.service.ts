import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EntityManager, MikroORM, RequestContext } from '@mikro-orm/core';
import {
  Application,
  ApplicationStatus,
  GrantType,
  Role,
  User,
  UserApplicationRole,
  UserStatus,
} from '../entities';
import { CredentialsService } from '../credentials/credentials.service';

/**
 * Idempotently seeds the bootstrap admin application + admin user from
 * ADMIN_BOOTSTRAP_* on first start, so a fresh deployment has a way in. Runs
 * only on the migration-owning (API) instance.
 */
@Injectable()
export class SeedService implements OnApplicationBootstrap {
  private readonly logger = new Logger(SeedService.name);

  static readonly ADMIN_CLIENT_ID = 'darboon-admin';
  static readonly ADMIN_AUDIENCE = 'darboon-admin';
  static readonly SUPERADMIN_ROLE = 'superadmin';

  constructor(
    private readonly orm: MikroORM,
    private readonly config: ConfigService,
    private readonly credentials: CredentialsService,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    if (process.env.DARBOON_ROLE === 'worker') return;
    const email = this.config.get<string>('ADMIN_BOOTSTRAP_EMAIL');
    const password = this.config.get<string>('ADMIN_BOOTSTRAP_PASSWORD');
    if (!email || !password) {
      this.logger.log('No ADMIN_BOOTSTRAP_* configured; skipping seed');
      return;
    }

    await RequestContext.create(this.orm.em, async () => {
      const em = this.orm.em.fork();
      const app = await this.ensureAdminApp(em);
      const role = await this.ensureSuperadminRole(em, app);
      await this.ensureAdminUser(em, app, role, email, password);
    });
  }

  private async ensureAdminApp(em: EntityManager): Promise<Application> {
    let app = await em.findOne(Application, {
      clientId: SeedService.ADMIN_CLIENT_ID,
    });
    if (!app) {
      app = em.create(Application, {
        clientId: SeedService.ADMIN_CLIENT_ID,
        name: 'Darboon Admin Console',
        audience: SeedService.ADMIN_AUDIENCE,
        redirectUris: [],
        allowedGrantTypes: [
          GrantType.PASSWORD,
          GrantType.REFRESH_TOKEN,
          GrantType.OTP,
        ],
        isFirstParty: true,
        requirePkce: false,
        status: ApplicationStatus.ACTIVE,
      } as unknown as Application);
      em.persist(app);
      await em.flush();
      this.logger.log('Seeded admin application');
    }
    return app;
  }

  private async ensureSuperadminRole(
    em: EntityManager,
    app: Application,
  ): Promise<Role> {
    let role = await em.findOne(Role, {
      applicationId: app.id,
      name: SeedService.SUPERADMIN_ROLE,
    });
    if (!role) {
      role = em.create(Role, {
        applicationId: app.id,
        name: SeedService.SUPERADMIN_ROLE,
        description: 'Full administrative access to Darboon',
        isDefault: false,
      } as Role);
      em.persist(role);
      await em.flush();
    }
    return role;
  }

  private async ensureAdminUser(
    em: EntityManager,
    app: Application,
    role: Role,
    email: string,
    password: string,
  ): Promise<void> {
    const normalized = email.toLowerCase();
    let user = await em.findOne(User, { email: normalized });
    if (!user) {
      user = em.create(User, {
        email: normalized,
        emailVerified: true,
        status: UserStatus.ACTIVE,
      } as User);
      em.persist(user);
      await em.flush();
      await this.credentials.setPassword(user.id, password);
      this.logger.log(`Seeded admin user ${normalized}`);
    }

    const assignment = await em.findOne(UserApplicationRole, {
      userId: user.id,
      applicationId: app.id,
      roleId: role.id,
    });
    if (!assignment) {
      const uar = em.create(UserApplicationRole, {
        userId: user.id,
        applicationId: app.id,
        roleId: role.id,
      } as UserApplicationRole);
      em.persist(uar);
      await em.flush();
    }
  }
}
