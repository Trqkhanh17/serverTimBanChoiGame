import { IsEmail, IsNotEmpty } from 'class-validator';

export class LoginLocalDto {
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  password: string;
}
