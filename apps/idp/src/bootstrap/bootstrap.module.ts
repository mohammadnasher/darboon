import { Module } from '@nestjs/common';
import { SeedService } from './seed.service';
import { CredentialsModule } from '../credentials/credentials.module';

@Module({
  imports: [CredentialsModule],
  providers: [SeedService],
})
export class BootstrapModule {}
