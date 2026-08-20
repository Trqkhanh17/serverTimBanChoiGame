import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomInt } from 'crypto';
import type { CreateOtpInput, VerifyOtpInput } from '@/common/types/otp.types';
import { MailService } from '@/mail/mail.service';
import { OtpService } from '@/modules/otp/otp.service';
import { UsersService } from '@/modules/users/users.service';
import { ResetPasswordDto } from '../dto/reset-password.dto';
import { AuthTokenService } from './auth-token.service';

@Injectable()
export class PasswordResetService {
  private readonly logger = new Logger(PasswordResetService.name);

  constructor(
    private readonly usersService: UsersService,
    private readonly otpService: OtpService,
    private readonly mailService: MailService,
    private readonly tokenService: AuthTokenService,
    private readonly configService: ConfigService,
  ) {}

  async request(email: string): Promise<void> {
    const user = await this.usersService.findUserByEmail(email);
    if (!user) {
      this.logger.warn(`Password reset requested for unknown email: ${email}`);
      return;
    }

    const otpCode = randomInt(100000, 1_000_000).toString();
    const expiresInMinutes = this.getOtpExpirationMinutes();
    const input: CreateOtpInput = {
      userId: user._id.toString(),
      expiresInMinutes,
      otpCode,
      purpose: 'forgot_password',
    };

    try {
      await this.otpService.createOtp(input);
      await this.mailService.sendOtpForgotPassword(email, otpCode, {
        name: user.name ?? user.email,
        expiresIn: expiresInMinutes,
      });
    } catch (error: unknown) {
      this.logger.error(
        `Failed to send forgot password OTP to ${email}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw new InternalServerErrorException(
        'Failed to send password reset email',
      );
    }
  }

  async verifyOtp(
    email: string,
    otpCode: string,
  ): Promise<{ reset_token: string }> {
    const user = await this.usersService.findUserByEmail(email);
    if (!user)
      throw new BadRequestException('OTP không hợp lệ hoặc đã hết hạn.');

    const input: VerifyOtpInput = {
      otpCode,
      purpose: 'forgot_password',
      userId: user._id.toString(),
    };
    if (!(await this.otpService.verifyOtp(input))) {
      throw new BadRequestException('OTP không hợp lệ hoặc đã hết hạn.');
    }

    return {
      reset_token: await this.tokenService.generateResetPasswordToken(
        user._id.toString(),
        user.email,
      ),
    };
  }

  async reset(input: ResetPasswordDto): Promise<{ message: string }> {
    if (input.newPassword !== input.confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    const payload = await this.tokenService.verifyResetPasswordToken(
      input.resetToken,
    );
    if (payload.type !== 'password_reset' || !payload.sub) {
      throw new BadRequestException('Reset token không hợp lệ.');
    }

    const currentVersion = await this.usersService.getRefreshTokenVersion(
      payload.sub,
    );
    if (currentVersion !== payload.tokenVersion) {
      throw new BadRequestException('Reset token đã được sử dụng.');
    }

    const changed = await this.usersService.changeUserPassword({
      userId: payload.sub,
      newPassword: input.newPassword,
    });
    if (!changed) throw new BadRequestException('Không thể đổi mật khẩu.');

    await this.usersService.revokeAllRefreshTokens(payload.sub);
    return { message: 'Password changed successfully' };
  }

  private getOtpExpirationMinutes(): number {
    return parseInt(
      this.configService.get<string>('OTP_FORGOT_PASSWORD_EXPIRE') ?? '5',
      10,
    );
  }
}
