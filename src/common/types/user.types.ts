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

export interface ChangePasswordInput {
  userId: string;
  newPassword: string;
}
export interface CheckPasswordInput {
  userId: string;
  password: string;
}

export enum Role {
  User = 'user',
  Admin = 'admin',
}
