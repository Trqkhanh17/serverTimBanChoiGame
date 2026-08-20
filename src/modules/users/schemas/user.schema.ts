import { Role } from '@/common/types/user.types';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import type { HydratedDocument } from 'mongoose';

export type UserDocument = HydratedDocument<User>;

@Schema({ timestamps: true })
export class User {
  @Prop({ unique: true, required: true, lowercase: true, trim: true })
  email: string;

  @Prop({ required: true, select: false })
  password: string;

  @Prop({ unique: true, required: true, trim: true })
  username: string;

  @Prop({ type: String, enum: Role, default: Role.User })
  role: Role;

  @Prop()
  name: string;

  @Prop()
  phone: string;

  @Prop()
  avatarUrl: string;

  @Prop()
  bio: string;

  @Prop()
  gender: 'male' | 'female';

  @Prop()
  birthDate: string;

  @Prop({ default: 'local', select: false })
  authProvider: string;

  @Prop()
  lastLogin: Date;

  @Prop({ default: false })
  isActive: boolean;

  @Prop({ select: false })
  refreshToken: string;

  @Prop({ default: 0 })
  refreshTokenVersion: number;

  @Prop({ default: false })
  isBanned: boolean;

  @Prop({ type: Date, default: null })
  emailVerifiedAt?: Date;

  @Prop({ type: String, default: null })
  verifyJti?: string | null;
}
export const UserSchema = SchemaFactory.createForClass(User);
