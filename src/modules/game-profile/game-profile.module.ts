import { Module } from '@nestjs/common';
import { GameProfileService } from './game-profile.service';
import { GameProfileController } from './game-profile.controller';

@Module({
  controllers: [GameProfileController],
  providers: [GameProfileService],
})
export class GameProfileModule {}
