import { Module } from '@nestjs/common';
import { MatchSearchService } from './match-search.service';
import { MatchSearchController } from './match-search.controller';

@Module({
  controllers: [MatchSearchController],
  providers: [MatchSearchService],
})
export class MatchSearchModule {}
