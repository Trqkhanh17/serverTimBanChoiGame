import { Test, TestingModule } from '@nestjs/testing';
import { MatchSearchController } from './match-search.controller';
import { MatchSearchService } from './match-search.service';

describe('MatchSearchController', () => {
  let controller: MatchSearchController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [MatchSearchController],
      providers: [MatchSearchService],
    }).compile();

    controller = module.get<MatchSearchController>(MatchSearchController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
