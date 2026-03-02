import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
} from '@nestjs/common';
import { GameProfileService } from './game-profile.service';
import { CreateGameProfileDto } from './dto/create-game-profile.dto';
import { UpdateGameProfileDto } from './dto/update-game-profile.dto';
import { JwtAccessGuard } from '@/auth/passport/guards/jwt-access.guard';
import { CurrentUser } from '@/common/decorators/user.decorator';

@Controller('game-profile')
@UseGuards(JwtAccessGuard)
export class GameProfileController {
  constructor(private readonly gameProfileService: GameProfileService) {}

  @Post()
  create(
    @CurrentUser('_id') userId: string,
    @Body() createGameProfileDto: CreateGameProfileDto,
  ) {
    return this.gameProfileService.create(userId, createGameProfileDto);
  }

  @Get()
  findAll(@CurrentUser('_id') userId: string) {
    return this.gameProfileService.findAll(userId);
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.gameProfileService.findOne(id);
  }

  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateGameProfileDto: UpdateGameProfileDto,
  ) {
    return this.gameProfileService.update(id, updateGameProfileDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.gameProfileService.remove(id);
  }
}
