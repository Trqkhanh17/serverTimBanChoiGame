import { UserResponseDto } from '@/modules/users/dto/user-response.dto';

export class AuthResponseDto {
  message: string;
  access_token: string;
  refresh_token: string;
  user: UserResponseDto;
}
