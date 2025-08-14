import { PartialType } from '@nestjs/mapped-types';
import { CreateMatchSearchDto } from './create-match-search.dto';

export class UpdateMatchSearchDto extends PartialType(CreateMatchSearchDto) {}
