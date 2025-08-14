import {
  Controller,
  Post,
  Body,
  BadRequestException,
  HttpCode,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '@/modules/users/dto/create-user.dto';
import { LoginRequestDto } from '@/auth/dto/login.Dto ';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @HttpCode(200)
  async login(@Body() data: LoginRequestDto) {
    const { email, password } = data;
    const user = await this.authService.login(email, password);
    if (!user) throw new BadRequestException('Đã có lỗi xảy ra');
    return user;
  }
  @Post('register')
  @HttpCode(201)
  async register(@Body() data: CreateUserDto) {
    return await this.authService.register(data);
  }
}
