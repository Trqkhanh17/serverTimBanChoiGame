import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type UserDocument = User & Document & { _id: string };

@Schema({ timestamps: true })
export class User extends Document {
  @Prop({ unique: true, required: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ unique: true, required: true })
  username: string;

  @Prop()
  name: string;

  @Prop()
  avatarUrl: string;

  @Prop()
  bio: string;

  @Prop()
  gender: 'male' | 'female';

  @Prop()
  birthDate: Date;

  @Prop({ default: 'local' })
  authProvider: string;

  @Prop()
  lastLogin: Date;

  @Prop({ default: false })
  isActive: boolean;

  @Prop()
  otpCode: string;

  @Prop()
  otpExpiresAt: Date;

  @Prop()
  resetPasswordToken: string;

  @Prop()
  resetPasswordExpires: Date;
}
export const UserSchema = SchemaFactory.createForClass(User);
