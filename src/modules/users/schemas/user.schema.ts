import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

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
  birthDate: string;

  @Prop({ default: 'local' })
  authProvider: string;

  @Prop()
  lastLogin: Date;

  @Prop({ default: false })
  isActive: boolean;

  @Prop()
  refreshToken: string;

  @Prop({ default: false })
  isBanned: boolean;
}
export const UserSchema = SchemaFactory.createForClass(User);
