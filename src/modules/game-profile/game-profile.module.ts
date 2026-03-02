import { Module } from '@nestjs/common';
import { GameProfileService } from './game-profile.service';
import { GameProfileController } from './game-profile.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { GameProfile, GameProfileSchema } from './schemas/game-profile.schema';
import { GameProfileRepository } from './game-profile.repository';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: GameProfile.name, schema: GameProfileSchema },
    ]),
  ],
  controllers: [GameProfileController],
  providers: [GameProfileService, GameProfileRepository],
})
export class GameProfileModule {}
