import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from '@nestjs/config';
import { TripPlan, TripPlanSchema } from './schemas/trip-plan.schema';
import { TripPlannerController } from './trip-planner.controller';
import { TripPlannerService } from './trip-planner.service';
import { GeminiAiService } from './services/gemini-ai.service';

@Module({
  imports: [
    ConfigModule,
    MongooseModule.forFeature([
      { name: TripPlan.name, schema: TripPlanSchema },
    ]),
  ],
  controllers: [TripPlannerController],
  providers: [TripPlannerService, GeminiAiService],
  exports: [TripPlannerService, GeminiAiService],
})
export class TripPlannerModule {}
