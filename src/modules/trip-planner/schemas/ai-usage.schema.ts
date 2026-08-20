import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import type { HydratedDocument } from 'mongoose';

export type AiUsageDocument = HydratedDocument<AiUsage>;

@Schema({ timestamps: true })
export class AiUsage {
  @Prop({ required: true, select: false })
  identityHash: string;

  @Prop({ required: true })
  day: string;

  @Prop({ required: true, default: 0, min: 0 })
  count: number;

  @Prop({ required: true })
  expiresAt: Date;
}

export const AiUsageSchema = SchemaFactory.createForClass(AiUsage);
AiUsageSchema.index({ identityHash: 1, day: 1 }, { unique: true });
AiUsageSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
