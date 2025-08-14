import { Injectable } from '@nestjs/common';
import { CreateGameProfileDto } from './dto/create-game-profile.dto';
import { UpdateGameProfileDto } from './dto/update-game-profile.dto';

@Injectable()
export class GameProfileService {
  create(createGameProfileDto: CreateGameProfileDto) {
    return 'This action adds a new gameProfile';
  }

  findAll() {
    return `This action returns all gameProfile`;
  }

  findOne(id: number) {
    return `This action returns a #${id} gameProfile`;
  }

  update(id: number, updateGameProfileDto: UpdateGameProfileDto) {
    return `This action updates a #${id} gameProfile`;
  }

  remove(id: number) {
    return `This action removes a #${id} gameProfile`;
  }
}
