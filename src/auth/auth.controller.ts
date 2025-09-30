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
import type {
  InputChangePasswordAuth,
  RequestWithUser,
  RequestWithUserAndRefreshToken,
} from '@/common/types/auth.types';
import { ChangePasswordForget } from '@/auth/dto/change.password.forgot.dto';
import { minutes, Throttle } from '@nestjs/throttler';
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Throttle({
    default: { limit: 10, ttl: minutes(1), blockDuration: minutes(5) },
  })
  @Post('login')
  @HttpCode(200)
  async login(@Request() req: RequestWithUser) {
    return await this.authService.login(req.user);
  }

  @Throttle({
    default: { limit: 3, ttl: minutes(1), blockDuration: minutes(5) },
  })
  @Post('register')
  @HttpCode(201)
  async register(@Body() data: RegisterDto) {
    return await this.authService.register(data);
  }

  @UseGuards(JwtAccessGuard)
  @Get('profile')
  @HttpCode(200)
  async getProfileUser(@Request() req: RequestWithUser) {
    const user = req.user;
    return await this.authService.getProfileUser(user);
  }

  @UseGuards(JwtRefreshGuard)
  @Post('refresh')
  @HttpCode(200)
  async refresh(@Request() req: RequestWithUserAndRefreshToken) {
    const { user, refreshToken } = req;
    const access_token = await this.authService.generateAccessToken(
      user,
      refreshToken,
      user.tokenVersion,
    );
    return {
      access_token,
    };
  }

  @UseGuards(JwtAccessGuard)
  @Throttle({
    default: { limit: 120, ttl: minutes(1), blockDuration: minutes(1) },
  })
  @Patch('profile')
  @HttpCode(200)
  async updateProfile(
    @Request() req: RequestWithUser,
    @Body() body: UpdateUserDto,
  ) {
    const { user } = req;
    if (!user) throw new BadRequestException();
    return this.authService.updateProfileUser(user._id, body);
  }

  @Throttle({
    default: { limit: 3, ttl: minutes(5), blockDuration: minutes(5) },
  })
  @Post('forgot-password')
  @HttpCode(202)
  async forgotPassword(@Body() input: EmailValidateDto) {
    await this.authService.sendUserForgotPassword(input.email.toString());
  }

  @UseGuards(JwtAccessGuard)
  @Throttle({
    default: { limit: 3, ttl: minutes(15), blockDuration: minutes(15) },
  })
  @Patch('change-password')
  async changePassword(
    @Request() req: RequestWithUser,
    @Body() data: ChangePasswordDto,
  ) {
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
  async changePasswordForgot(@Body() body: ChangePasswordForget) {
    return this.authService.changePasswordForgot();
  }

  @UseGuards(JwtRefreshGuard)
  @Delete('logout')
  async logOut(@Request() req: RequestWithUser) {
    return await this.authService.logout(req.user._id);
  }

  @Get('verify-email')
  async verifyEmail(@Query('token') token: string) {
    const result = await this.authService.verifyEmailToken(token);
    return result;
  }
  @Post('forgot-password-verify')
  async verifyOtpForgot() {}
}
