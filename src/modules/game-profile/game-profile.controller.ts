import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { GameProfileService } from './game-profile.service';
import { CreateGameProfileDto } from './dto/create-game-profile.dto';
import { UpdateGameProfileDto } from './dto/update-game-profile.dto';

@Controller('game-profile')
export class GameProfileController {
  constructor(private readonly gameProfileService: GameProfileService) {}

  @Post()
  create(@Body() createGameProfileDto: CreateGameProfileDto) {
    return this.gameProfileService.create(createGameProfileDto);
  }

  @Get()
  findAll() {
    return this.gameProfileService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.gameProfileService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateGameProfileDto: UpdateGameProfileDto) {
    return this.gameProfileService.update(+id, updateGameProfileDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.gameProfileService.remove(+id);
  }
}
