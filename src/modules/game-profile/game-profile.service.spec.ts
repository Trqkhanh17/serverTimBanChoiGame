import { Test, TestingModule } from '@nestjs/testing';
import { GameProfileService } from './game-profile.service';

describe('GameProfileService', () => {
  let service: GameProfileService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [GameProfileService],
    }).compile();

    service = module.get<GameProfileService>(GameProfileService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
