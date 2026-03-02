import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

@Schema({ timestamps: true })
export class GameProfile extends Document {
  @Prop({ type: Types.ObjectId, ref: 'User', required: true })
  userId: Types.ObjectId;

  @Prop({ required: true })
  ign: string;

  @Prop()
  rank: string;

  @Prop()
  level: number;

  @Prop()
  bio: string;

  @Prop({ type: [String], default: [] })
  mainPositions: string[];

  @Prop({ default: true })
  isActive: boolean;
}

export const GameProfileSchema = SchemaFactory.createForClass(GameProfile);
