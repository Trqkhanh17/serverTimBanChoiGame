import {
  IsEmail,
  IsString,
  IsOptional,
  IsDate,
  IsEnum,
  IsNotEmpty,
  MinLength,
  MaxLength,
} from 'class-validator';

export class CreateUserDto {
  @IsNotEmpty({ message: 'Email không được rỗng' })
  @IsEmail({}, { message: 'Email không đúng định dạng' })
  email: string;

  @IsNotEmpty({ message: 'Mật khẩu không được để trống' })
  @IsString()
  @MinLength(8, { message: 'Mật khẩu phải từ 8 ký tự trở lên' })
  password: string;

  @IsNotEmpty({ message: 'user name không được rỗng' })
  @IsString()
  @MinLength(4, { message: 'User name phải có từ 4 ký tự trở lên' })
  @MaxLength(20, { message: 'User name không được vượt quá 20 ký tự' })
  username: string;

  @IsOptional()
  @IsEnum(['male', 'female'])
  gender?: string;

  @IsOptional()
  @IsString()
  phone: string;

  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsString()
  avatarUrl?: string;

  @IsOptional()
  @IsString()
  bio?: string;

  @IsOptional()
  @IsDate({ message: 'Vui lòng chọn ngày tháng năm sinh hợp lệ' })
  birthDate?: Date;
}
