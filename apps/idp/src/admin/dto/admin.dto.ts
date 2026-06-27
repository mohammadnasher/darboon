import {
  ArrayUnique,
  IsArray,
  IsBoolean,
  IsIn,
  IsOptional,
  IsString,
  MaxLength,
} from 'class-validator';
import { GrantType } from '../../entities';

export class CreateApplicationDto {
  @IsString() @MaxLength(200) name!: string;
  @IsString() @MaxLength(255) audience!: string;

  @IsOptional() @IsString() clientId?: string;
  @IsOptional() @IsArray() @IsString({ each: true }) redirectUris?: string[];
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  allowedGrantTypes?: GrantType[];
  @IsOptional() @IsBoolean() confidential?: boolean;
  @IsOptional() @IsBoolean() requirePkce?: boolean;
}

export class UpdateApplicationDto {
  @IsOptional() @IsString() @MaxLength(200) name?: string;
  @IsOptional() @IsArray() @IsString({ each: true }) redirectUris?: string[];
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  allowedGrantTypes?: GrantType[];
  @IsOptional() @IsIn(['active', 'disabled']) status?: 'active' | 'disabled';
}

export class CreateRoleDto {
  @IsString() @MaxLength(150) name!: string;
  @IsOptional() @IsString() description?: string;
  @IsOptional() @IsBoolean() isDefault?: boolean;
}

export class CreatePermissionDto {
  @IsString() @MaxLength(200) name!: string;
  @IsOptional() @IsString() description?: string;
}

export class SetRolePermissionsDto {
  @IsArray() @ArrayUnique() @IsString({ each: true }) permissionIds!: string[];
}

export class AssignRoleDto {
  @IsString() applicationId!: string;
  @IsString() roleId!: string;
}

export class UpdateUserStatusDto {
  @IsIn(['active', 'locked', 'disabled', 'pending'])
  status!: 'active' | 'locked' | 'disabled' | 'pending';
}
