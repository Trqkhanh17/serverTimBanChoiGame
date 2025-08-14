import { Test, TestingModule } from '@nestjs/testing';
import { MatchSearchService } from './match-search.service';

describe('MatchSearchService', () => {
  let service: MatchSearchService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [MatchSearchService],
    }).compile();

    service = module.get<MatchSearchService>(MatchSearchService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
