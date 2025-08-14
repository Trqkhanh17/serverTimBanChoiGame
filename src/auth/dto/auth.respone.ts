export class AuthResponseDto {
  access_token: string;
  refresh_token: string;
  user: UserResponseDto;
}
export class UserResponseDto {
  _id: string;
  email: string;
  username: string;
  name: string;
  avatarUrl?: string;
  bio?: string;
  isActive: boolean;
  gender?: string;
  birthDate?: Date;
}
