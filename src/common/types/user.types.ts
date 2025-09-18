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
export interface UserCreateInput {
  email: string;
  passwordHash: string;
  username: string;
  name: string;
}

export interface UserUpdateInput {
  name?: string;
  phone?: string;
  avatarUrl?: string;
  bio?: string;
  gender?: 'male' | 'female';
  birthDate?: string;
}

export interface changePasswordInPut {
  userId: string;
  newPassword: string;
}
export interface checkPasswordInPut {
  userId: string;
  password: string;
}

export enum Role {
  User = 'user',
  Admin = 'admin',
}