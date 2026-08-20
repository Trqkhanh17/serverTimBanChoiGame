import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';
import type {
  BudgetBreakdown,
  DestinationInfo,
  ItineraryDay,
  RecommendedSpots,
} from '../dto/trip-plan-response.dto';
import type { CreateTripPlanDto } from '../dto/create-trip-plan.dto';

export type TripPlanDocument = TripPlan & Document;

@Schema({ timestamps: true })
export class TripPlan {
  @Prop({
    type: MongooseSchema.Types.ObjectId,
    ref: 'User',
    default: null,
    index: true,
  })
  userId?: string;

  @Prop({ type: Object, required: true })
  inputCriteria: CreateTripPlanDto;

  @Prop({ type: Object, required: true })
  destination: DestinationInfo;

  @Prop({ type: Object, required: true })
  budgetBreakdown: BudgetBreakdown;

  @Prop({ type: Array, required: true })
  itinerary: ItineraryDay[];

  @Prop({ type: Object, required: true })
  recommendedSpots: RecommendedSpots;

  @Prop({ type: [String], default: [] })
  travelTips: string[];

  @Prop({ type: Boolean, default: false })
  isPublic: boolean;
}

export const TripPlanSchema = SchemaFactory.createForClass(TripPlan);
