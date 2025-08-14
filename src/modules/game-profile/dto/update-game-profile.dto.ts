import { PartialType } from '@nestjs/mapped-types';
import { CreateGameProfileDto } from './create-game-profile.dto';

export class UpdateGameProfileDto extends PartialType(CreateGameProfileDto) {}
