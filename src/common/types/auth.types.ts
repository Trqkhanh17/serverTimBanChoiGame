import { UserDocument } from '@/modules/users/schemas/user.schema';

export interface TokenUser {
  _id: string;
  email: string;
  username: string;
}
export type UserWithoutPassword = Omit<UserDocument, 'password'>;

export interface AuthRequest {
  user: UserWithoutPassword;
}
export type RequestWithUser = Request & { user: UserWithoutPassword };

export interface TokenPayload {
  _id: string;
  email: string;
}
