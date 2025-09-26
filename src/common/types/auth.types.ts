import { UserResponseDto } from '@/modules/users/dto/user-response.dto';

export interface AuthUser {
  _id: string;
  email: string;
  name: string;
  username: string;
  isActive: boolean;
  isBanned: boolean;
}

export interface InputChangePasswordAuth {
  newPassword: string;
  oldPassword: string;
  comFirmPassword: string;
  userId: string;
}

export interface RequestWithUser extends Request {
  user: UserResponseDto;
}
export interface RequestWithUserAndRefreshToken extends Request {
  user: UserResponseDto;
  refreshToken: string;
}
