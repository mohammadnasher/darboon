import { Module } from '@nestjs/common';
import { AdminService } from './admin.service';
import { AdminController } from './admin.controller';
import { RbacModule } from '../rbac/rbac.module';
import { KeysModule } from '../keys/keys.module';

@Module({
  imports: [RbacModule, KeysModule],
  controllers: [AdminController],
  providers: [AdminService],
})
export class AdminModule {}
