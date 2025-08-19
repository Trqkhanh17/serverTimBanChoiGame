import { User } from '@/modules/users/schemas/user.schema';
import { Document } from 'mongoose';

export type UserResponse = Omit<
  User,
  | 'password'
  | 'otpCode'
  | 'otpExpiresAt'
  | 'resetPasswordToken'
  | 'resetPasswordExpires'
>;

export type UserDocument = User & Document & { _id: string };
