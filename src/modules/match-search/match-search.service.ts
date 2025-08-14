import { Injectable } from '@nestjs/common';
import { CreateMatchSearchDto } from './dto/create-match-search.dto';
import { UpdateMatchSearchDto } from './dto/update-match-search.dto';

@Injectable()
export class MatchSearchService {
  create(createMatchSearchDto: CreateMatchSearchDto) {
    return 'This action adds a new matchSearch';
  }

  findAll() {
    return `This action returns all matchSearch`;
  }

  findOne(id: number) {
    return `This action returns a #${id} matchSearch`;
  }

  update(id: number, updateMatchSearchDto: UpdateMatchSearchDto) {
    return `This action updates a #${id} matchSearch`;
  }

  remove(id: number) {
    return `This action removes a #${id} matchSearch`;
  }
}
