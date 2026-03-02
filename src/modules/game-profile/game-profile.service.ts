import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateGameProfileDto } from './dto/create-game-profile.dto';
import { UpdateGameProfileDto } from './dto/update-game-profile.dto';
import { GameProfileRepository } from './game-profile.repository';
import { Types } from 'mongoose';

@Injectable()
export class GameProfileService {
  constructor(private readonly gameProfileRepository: GameProfileRepository) {}

  async create(userId: string, createGameProfileDto: CreateGameProfileDto) {
    return this.gameProfileRepository.create({
      ...createGameProfileDto,
      userId: new Types.ObjectId(userId),
    });
  }

  async findAll(userId: string) {
    return this.gameProfileRepository.find({
      userId: new Types.ObjectId(userId),
    });
  }

  async findOne(id: string) {
    const profile = await this.gameProfileRepository.findById(id);
    if (!profile) {
      throw new NotFoundException(`Game profile with ID ${id} not found`);
    }
    return profile;
  }

  async update(id: string, updateGameProfileDto: UpdateGameProfileDto) {
    const profile = await this.gameProfileRepository.findByIdAndUpdate(
      id,
      updateGameProfileDto,
    );
    if (!profile) {
      throw new NotFoundException(`Game profile with ID ${id} not found`);
    }
    return profile;
  }

  async remove(id: string) {
    const result = await this.gameProfileRepository.updateOne(
      { _id: new Types.ObjectId(id) },
      { isActive: false },
    );
    if (result.matchedCount === 0) {
      throw new NotFoundException(`Game profile with ID ${id} not found`);
    }
    return { success: true };
  }
}
