import {
  Controller,
  Post,
  Body,
  BadRequestException,
  HttpCode,
  UseGuards,
  Request,
  Get,
  BadGatewayException,
  Patch,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '@/modules/users/dto/create-user.dto';
import { LocalAuthGuard } from '@/auth/passport/guards/local-auth.guard';
import { JwtAccessGuard } from '@/auth/passport/guards/jwt-auth.guard';
import { JwtRefreshGuard } from '@/auth/passport/guards/jwt-refresh.guard';
import { UpdateAuthDto } from '@/auth/dto/update-auth.dto';
import { UpdateUserDto } from '@/modules/users/dto/update-user.dto';
import { ResetPasswordDto } from '@/modules/users/dto/reset-password.user.Dto';
import { JwtResetPasswordGuard } from '@/auth/passport/guards/jwt-reset-password.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  @HttpCode(200)
  async login(@Request() req) {
    const user = await this.authService.login(req.user);
    if (!user) throw new BadRequestException('Đã có lỗi xảy ra');
    return user;
  }

  @Post('register')
  @HttpCode(201)
  async register(@Body() data: CreateUserDto) {
    return await this.authService.register(data);
  }

  @UseGuards(JwtAccessGuard)
  @Get('profile')
  @HttpCode(200)
  async getProfileUser(@Request() req) {
    const user = req.user;
    return await this.authService.getProfileUser(user);
  }

  @Post('refresh')
  @UseGuards(JwtRefreshGuard)
  @HttpCode(201)
  async refresh(@Request() req) {
    const user = req.user;
    const result = await this.authService.getUserByid(user._id);
    const access_token = await this.authService.generateAccessToken(result);
    return {
      access_token,
    };
  }

  @Patch('profile')
  @UseGuards(JwtAccessGuard)
  @HttpCode(200)
  async udpateProfile(@Request() req, @Body() body: UpdateUserDto) {
    const { user } = req;
    if (!user) throw new BadRequestException();
    return this.authService.updateProfileUser(user.email, body);
  }

  @Post('forgot-password')
  @HttpCode(201)
  async forgotPassword(@Body('email') email: string) {
    const reset_paswordtoken =
      await this.authService.generateRessetPasswordToken(email);
    return {
      reset_paswordtoken: reset_paswordtoken,
    };
  }

  @Patch('reset-password')
  @UseGuards(JwtResetPasswordGuard)
  async resetPassword(@Request() req, @Body() password: ResetPasswordDto) {
    const user = req.user;
    if (!user) throw new BadRequestException();
    if (!password) throw new BadRequestException();
    const result = await this.authService.resetPassword(user.email, password);
    if (!result) return 'Thay đổi mật khẩu thất bại';
    return 'Thay đổi mật khẩu thành công';
  }
}
