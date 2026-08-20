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
import { RegisterDto } from '@/auth/dto/register-user.dto';
import {
  EmailValidateDto,
  VerifyForgotPasswordOtpDto,
} from '@/auth/dto/forgot-password.dto';
import { ChangePasswordDto } from '@/auth/dto/change-password.dto';
import type {
  ChangeOwnPasswordInput,
  RequestWithUser,
  RequestWithUserAndRefreshToken,
} from '@/common/types/auth.types';
import { ResetPasswordDto } from '@/auth/dto/reset-password.dto';
import { minutes, Throttle } from '@nestjs/throttler';
import { EmailVerificationService } from './services/email-verification.service';
import { PasswordResetService } from './services/password-reset.service';
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly emailVerificationService: EmailVerificationService,
    private readonly passwordResetService: PasswordResetService,
  ) {}

  @UseGuards(LocalAuthGuard)
  @Throttle({
    default: { limit: 10, ttl: minutes(1), blockDuration: minutes(5) },
  })
  @Post('login')
  @HttpCode(200)
  async login(@Request() req: RequestWithUser) {
    return this.authService.login(req.user);
  }

  @Throttle({
    default: { limit: 3, ttl: minutes(1), blockDuration: minutes(5) },
  })
  @Post('register')
  @HttpCode(201)
  async register(@Body() data: RegisterDto) {
    return this.authService.register(data);
  }

  @UseGuards(JwtAccessGuard)
  @Get('profile')
  @HttpCode(200)
  async getProfileUser(@Request() req: RequestWithUser) {
    const user = req.user;
    return this.authService.getProfileUser(user);
  }

  @UseGuards(JwtRefreshGuard)
  @Post('refresh')
  @HttpCode(200)
  async refresh(@Request() req: RequestWithUserAndRefreshToken) {
    const { user, refreshToken } = req;
    return this.authService.refresh(user, refreshToken);
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
    await this.passwordResetService.request(input.email);
    return {
      message: 'Nếu email tồn tại, mã OTP đã được gửi.',
    };
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
    const changePasswordInput: ChangeOwnPasswordInput = {
      confirmPassword: data.confirmPassword,
      newPassword: data.newPassword,
      oldPassword: data.oldPassword,
      userId: userId,
    };
    return this.authService.changePassword(changePasswordInput);
  }

  @Patch('change-password-forgot')
  @Throttle({
    default: { limit: 5, ttl: minutes(15), blockDuration: minutes(15) },
  })
  async changePasswordForgot(@Body() body: ResetPasswordDto) {
    return this.passwordResetService.reset(body);
  }

  @UseGuards(JwtRefreshGuard)
  @Delete('logout')
  async logOut(@Request() req: RequestWithUser) {
    return this.authService.logout(req.user._id);
  }

  @Get('verify-email')
  async verifyEmail(@Query('token') token: string) {
    return this.emailVerificationService.verify(token);
  }
  @Post('forgot-password-verify')
  @HttpCode(200)
  @Throttle({
    default: { limit: 5, ttl: minutes(15), blockDuration: minutes(15) },
  })
  async verifyOtpForgot(@Body() body: VerifyForgotPasswordOtpDto) {
    return this.passwordResetService.verifyOtp(body.email, body.otpCode);
  }

  @Post('resend-verification')
  @HttpCode(202)
  @Throttle({
    default: { limit: 3, ttl: minutes(15), blockDuration: minutes(15) },
  })
  async resendVerification(@Body() body: EmailValidateDto) {
    await this.emailVerificationService.resend(body.email);
    return { message: 'Nếu tài khoản chưa xác minh, email mới đã được gửi.' };
  }
}
