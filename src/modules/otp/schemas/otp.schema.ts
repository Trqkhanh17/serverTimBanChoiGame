import type { OtpPurpose } from '@/common/types/opt.types';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class Otp {
  @Prop({ required: true })
  userId: string;

  @Prop({ required: true })
  otpCode: string;

  @Prop({ required: true })
  otpExpiresAt: Date;

  @Prop({ required: true, enum: ['reset_phone', 'reset_password'] })
  purpose: OtpPurpose;

  @Prop({ default: false })
  used: boolean;
}

export const OtpSchema = SchemaFactory.createForClass(Otp);
