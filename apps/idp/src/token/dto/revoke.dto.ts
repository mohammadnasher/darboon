import { IsIn, IsOptional, IsString } from 'class-validator';

export class RevokeDto {
  @IsString()
  client_id!: string;

  @IsOptional()
  @IsString()
  client_secret?: string;

  @IsString()
  token!: string;

  @IsOptional()
  @IsIn(['access_token', 'refresh_token'])
  token_type_hint?: 'access_token' | 'refresh_token';
}

export class IntrospectDto {
  @IsString()
  token!: string;

  @IsOptional()
  @IsIn(['access_token', 'refresh_token'])
  token_type_hint?: 'access_token' | 'refresh_token';
}
