import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { AbstractRepository } from '@/common/repositories/abstract.repository';
import { GameProfile } from './schemas/game-profile.schema';

@Injectable()
export class GameProfileRepository extends AbstractRepository<GameProfile> {
  constructor(
    @InjectModel(GameProfile.name)
    private readonly gameProfileModel: Model<GameProfile>,
  ) {
    super(gameProfileModel);
  }
}
