import {
  Controller,
  Post,
  Body,
  BadRequestException,
  HttpCode,
  UseGuards,
  Request,
  Get,
  Patch,
  Delete,
  Query,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from '@/auth/passport/guards/local-auth.guard';
import { JwtAccessGuard } from '@/auth/passport/guards/jwt-access.guard';
import { JwtRefreshGuard } from '@/auth/passport/guards/jwt-refresh.guard';
import { UpdateUserDto } from '@/auth/dto/update-user.dto';
import { RegisterDto } from '@/auth/dto/register.Dto';
import { EmailValidateDto } from '@/auth/dto/forgot-password.dto';
import { ChangePasswordDto } from '@/auth/dto/change-password.dto';
import { InputChangePasswordAuth } from '@/common/types/auth.types';
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  @HttpCode(200)
  async login(@Request() req) {
    return await this.authService.login(req.user);
  }

  @Post('register')
  @HttpCode(201)
  async register(@Body() data: RegisterDto) {
    console.log('dto: ', data);

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
  @HttpCode(200)
  async refresh(@Request() req) {
    const { user, refreshToken } = await req;
    const access_token = await this.authService.generateAccessToken(
      user,
      refreshToken,
    );
    return {
      access_token,
    };
  }

  @Patch('profile')
  @UseGuards(JwtAccessGuard)
  @HttpCode(200)
  async updateProfile(@Request() req, @Body() body: UpdateUserDto) {
    const { user } = req;
    if (!user) throw new BadRequestException();
    return this.authService.updateProfileUser(user._id, body);
  }

  @Post('forgot-password')
  @HttpCode(201)
  async forgotPassword(@Body() input: EmailValidateDto) {
    await this.authService.sendUserForgotPassword(input.email.toString());
  }

  @UseGuards(JwtAccessGuard)
  @Patch('change-password')
  async changePassword(@Request() req, @Body() data: ChangePasswordDto) {
    const userId = req.user._id;
    const inPutChangePassword: InputChangePasswordAuth = {
      comFirmPassword: data.comFirmPassword,
      newPassword: data.newPassword,
      oldPassword: data.oldPassword,
      userId: userId,
    };
    return await this.authService.changePassword(inPutChangePassword);
  }

  @Patch('change-password-forgot')
  async changePasswordForgot(@Body() input) {}

  @UseGuards(JwtRefreshGuard)
  @Delete('logout')
  async logOut(@Request() req) {
    return await this.authService.logout(req.user._id);
  }

  @Get('verify-email')
  async verifyEmail(@Query('token') token: string) {
    const result = await this.authService.verifyEmailToken(token);
    return result;
  }
}
