import { IsEmail, IsNotEmpty } from 'class-validator';

export class LoginRequestDto {
  @IsNotEmpty()
  @IsEmail({}, { message: 'Email không đúng định dạng' })
  email: string;
  @IsNotEmpty()
  password: string;
}
