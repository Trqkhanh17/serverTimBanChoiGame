import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type OtpDocument = Otp & Document;

export type OtpPurpose = 'reset_phone' | 'reset_password';

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
