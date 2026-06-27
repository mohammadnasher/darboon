import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Put,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import { AdminService } from './admin.service';
import { KeyService } from '../keys/key.service';
import { ApiKeyGuard } from '../common/guards/api-key.guard';
import {
  AssignRoleDto,
  CreateApplicationDto,
  CreatePermissionDto,
  CreateRoleDto,
  SetRolePermissionsDto,
  UpdateApplicationDto,
  UpdateUserStatusDto,
} from './dto/admin.dto';
import { UserStatus } from '../entities';

/**
 * Admin RBAC + client management API. Authenticated machine-to-machine via the
 * `X-API-Key` header (ADMIN_API_KEY_HASH). The minimal admin console (served
 * from dist/public) calls these endpoints.
 */
@Controller('admin')
@UseGuards(ApiKeyGuard)
export class AdminController {
  constructor(
    private readonly admin: AdminService,
    private readonly keys: KeyService,
  ) {}

  // ── Applications ────────────────────────────────────────────────────────────
  @Get('applications')
  listApplications() {
    return this.admin.listApplications();
  }

  @Post('applications')
  createApplication(@Body() dto: CreateApplicationDto) {
    return this.admin.createApplication(dto);
  }

  @Get('applications/:id')
  getApplication(@Param('id') id: string) {
    return this.admin.getApplication(id);
  }

  @Patch('applications/:id')
  updateApplication(
    @Param('id') id: string,
    @Body() dto: UpdateApplicationDto,
  ) {
    return this.admin.updateApplication(id, dto);
  }

  @Delete('applications/:id')
  deleteApplication(@Param('id') id: string) {
    return this.admin.deleteApplication(id);
  }

  @Post('applications/:id/rotate-secret')
  rotateSecret(@Param('id') id: string) {
    return this.admin.rotateSecret(id);
  }

  // ── Roles & permissions ─────────────────────────────────────────────────────
  @Get('applications/:id/roles')
  listRoles(@Param('id') id: string) {
    return this.admin.listRoles(id);
  }

  @Post('applications/:id/roles')
  createRole(@Param('id') id: string, @Body() dto: CreateRoleDto) {
    return this.admin.createRole(id, dto);
  }

  @Delete('roles/:roleId')
  deleteRole(@Param('roleId') roleId: string) {
    return this.admin.deleteRole(roleId);
  }

  @Put('roles/:roleId/permissions')
  setRolePermissions(
    @Param('roleId') roleId: string,
    @Body() dto: SetRolePermissionsDto,
  ) {
    return this.admin.setRolePermissions(roleId, dto);
  }

  @Get('applications/:id/permissions')
  listPermissions(@Param('id') id: string) {
    return this.admin.listPermissions(id);
  }

  @Post('applications/:id/permissions')
  createPermission(@Param('id') id: string, @Body() dto: CreatePermissionDto) {
    return this.admin.createPermission(id, dto);
  }

  // ── Users & assignments ─────────────────────────────────────────────────────
  @Get('users')
  listUsers(@Query('query') query?: string) {
    return this.admin.listUsers(query);
  }

  @Get('users/:id')
  getUser(@Param('id') id: string) {
    return this.admin.getUser(id);
  }

  @Patch('users/:id/status')
  updateUserStatus(@Param('id') id: string, @Body() dto: UpdateUserStatusDto) {
    return this.admin.updateUserStatus(id, dto.status as UserStatus);
  }

  @Get('users/:id/roles')
  listUserRoles(@Param('id') id: string) {
    return this.admin.listUserRoles(id);
  }

  @Post('users/:id/roles')
  assignRole(
    @Param('id') id: string,
    @Body() dto: AssignRoleDto,
    @Req() req: Request,
  ) {
    const actorId = req.headers['x-actor-id'];
    return this.admin.assignRole(
      id,
      dto,
      typeof actorId === 'string' ? actorId : undefined,
    );
  }

  @Delete('users/:id/roles/:assignmentId')
  revokeRole(
    @Param('id') id: string,
    @Param('assignmentId') assignmentId: string,
  ) {
    return this.admin.revokeRole(id, assignmentId);
  }

  // ── Sessions ────────────────────────────────────────────────────────────────
  @Get('users/:id/sessions')
  listSessions(@Param('id') id: string) {
    return this.admin.listSessions(id);
  }

  @Delete('users/:id/sessions')
  revokeSessions(@Param('id') id: string) {
    return this.admin.revokeAllSessions(id);
  }

  // ── Audit & keys ────────────────────────────────────────────────────────────
  @Get('audit')
  audit(
    @Query('eventType') eventType?: string,
    @Query('userId') userId?: string,
    @Query('limit') limit?: string,
  ) {
    return this.admin.queryAudit({
      eventType,
      userId,
      limit: limit ? parseInt(limit, 10) : undefined,
    });
  }

  @Post('keys/rotate')
  rotateKeys() {
    return this.keys.rotate();
  }
}
