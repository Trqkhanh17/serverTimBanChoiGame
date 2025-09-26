export class UserResponseDto {
  _id: string;
  email: string;
  username: string;
  name: string;
  isActive: boolean;
  bio?: string;
  gender?: string;
  birthDate?: string;
  avatarUrl?: string;
  isBanned?: boolean;
  role?: string;
}
