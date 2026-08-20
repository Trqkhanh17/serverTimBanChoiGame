import type { OtpPurpose } from '@/common/types/otp.types';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import type { HydratedDocument } from 'mongoose';

export type OtpDocument = HydratedDocument<Otp>;

@Schema({ timestamps: true })
export class Otp {
  @Prop({ required: true })
  userId: string;

  @Prop({ required: true })
  otpCode: string;

  @Prop({ required: true })
  otpExpiresAt: Date;

  @Prop({ required: true, enum: ['reset_phone', 'forgot_password'] })
  purpose: OtpPurpose;

  @Prop({ default: false })
  used: boolean;
}

export const OtpSchema = SchemaFactory.createForClass(Otp);
OtpSchema.index({ otpExpiresAt: 1 }, { expireAfterSeconds: 0 });
OtpSchema.index({ userId: 1, purpose: 1, createdAt: -1 });
