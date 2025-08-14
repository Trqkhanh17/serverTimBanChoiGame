import {
  Controller,
  Post,
  Body,
  BadRequestException,
  HttpCode,
  UseGuards,
  Request,
  Get,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '@/modules/users/dto/create-user.dto';
import { LocalAuthGuard } from '@/auth/passport/guards/local-auth.guard';
import type { AuthRequest, RequestWithUser } from '@/common/types/auth.types';
import { JwtAuthGuard } from '@/auth/passport/guards/jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  @HttpCode(200)
  async login(@Request() req: AuthRequest) {
    const user = await this.authService.login(req.user);
    if (!user) throw new BadRequestException('Đã có lỗi xảy ra');
    return user;
  }

  @Post('register')
  @HttpCode(201)
  async register(@Body() data: CreateUserDto) {
    return await this.authService.register(data);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  @HttpCode(200)
  async getProfileUser(@Request() req: RequestWithUser) {
    return await this.authService.getProfileUser(req.user);
  }
}
