import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class ResetPasswordDto {
  @IsNotEmpty()
  email: string;
  @IsNotEmpty({ message: 'Mật khẩu không được để trống' })
  @IsString()
  @MinLength(8, { message: 'Mật khẩu phải từ 8 ký tự trở lên' })
  password: string;
}
