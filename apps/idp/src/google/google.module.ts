import { Module } from '@nestjs/common';
import { GoogleService } from './google.service';
import { GoogleController } from './google.controller';
import { ApplicationsModule } from '../applications/applications.module';
import { TokenModule } from '../token/token.module';

@Module({
  imports: [ApplicationsModule, TokenModule],
  controllers: [GoogleController],
  providers: [GoogleService],
})
export class GoogleModule {}
