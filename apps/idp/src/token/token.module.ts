import { Module } from '@nestjs/common';
import { TokenService } from './token.service';
import { TokenVerifierService } from './token-verifier.service';
import { IntrospectionService } from './introspection.service';
import { AccessTokenGuard } from './access-token.guard';
import { OidcController } from './oidc.controller';
import { UserinfoController } from './userinfo.controller';
import { TokenController } from './token.controller';
import { KeysModule } from '../keys/keys.module';
import { RbacModule } from '../rbac/rbac.module';
import { ApplicationsModule } from '../applications/applications.module';
import { UsersModule } from '../users/users.module';

@Module({
  imports: [KeysModule, RbacModule, ApplicationsModule, UsersModule],
  controllers: [OidcController, UserinfoController, TokenController],
  providers: [
    TokenService,
    TokenVerifierService,
    IntrospectionService,
    AccessTokenGuard,
  ],
  exports: [TokenService, TokenVerifierService, AccessTokenGuard],
})
export class TokenModule {}
