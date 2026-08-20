import { UserResponseDto } from '@/modules/users/dto/user-response.dto';
import { Role } from '@/common/types/user.types';
import type { Request } from 'express';

export interface AuthUser {
  _id: string;
  email: string;
  name: string;
  username: string;
  isActive: boolean;
  isBanned: boolean;
  role: Role;
}

export interface ChangeOwnPasswordInput {
  newPassword: string;
  oldPassword: string;
  confirmPassword: string;
  userId: string;
}

export interface RequestWithUser extends Request {
  user: UserResponseDto;
}
export interface RequestWithUserAndRefreshToken extends Request {
  user: UserResponseDto;
  refreshToken: string;
}
export interface OptionalRequestWithUser extends Request {
  user?: UserResponseDto;
}
