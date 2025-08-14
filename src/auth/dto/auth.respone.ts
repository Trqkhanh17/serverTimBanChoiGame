export class AuthResponseDto {
  access_token: string;
  refresh_token: string;
  user: {
    _id: string;
    email: string;
    username: string;
    name: string;
    avatarUrl?: string;
    bio?: string;
  };
}
