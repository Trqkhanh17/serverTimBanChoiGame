import { Test, TestingModule } from '@nestjs/testing';
import { GameProfileController } from './game-profile.controller';
import { GameProfileService } from './game-profile.service';

describe('GameProfileController', () => {
  let controller: GameProfileController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [GameProfileController],
      providers: [GameProfileService],
    }).compile();

    controller = module.get<GameProfileController>(GameProfileController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
