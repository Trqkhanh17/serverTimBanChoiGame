import { IsNotEmpty, IsString, MaxLength, MinLength } from 'class-validator';

export class changePasswordForgotInput {
  @IsNotEmpty()
  @IsString()
  otpCode: string;

  @IsNotEmpty({ message: 'Password must not be empty' })
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @MaxLength(20, { message: 'Password must not exceed 20 characters' })
  newPassword: string;
}
