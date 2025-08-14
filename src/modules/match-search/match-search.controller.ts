import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { MatchSearchService } from './match-search.service';
import { CreateMatchSearchDto } from './dto/create-match-search.dto';
import { UpdateMatchSearchDto } from './dto/update-match-search.dto';

@Controller('match-search')
export class MatchSearchController {
  constructor(private readonly matchSearchService: MatchSearchService) {}

  @Post()
  create(@Body() createMatchSearchDto: CreateMatchSearchDto) {
    return this.matchSearchService.create(createMatchSearchDto);
  }

  @Get()
  findAll() {
    return this.matchSearchService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.matchSearchService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateMatchSearchDto: UpdateMatchSearchDto) {
    return this.matchSearchService.update(+id, updateMatchSearchDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.matchSearchService.remove(+id);
  }
}
