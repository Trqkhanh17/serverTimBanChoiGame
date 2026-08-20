import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import type { SignOptions } from 'jsonwebtoken';
import { UsersService } from '@/modules/users/users.service';
import { UserResponseDto } from '@/modules/users/dto/user-response.dto';
import { comparePassword } from '@/common/helpers/password.helpers';

export interface EmailVerificationPayload {
  sub: string;
  type: 'email_verify';
  jti: string;
}

export interface ResetPasswordPayload {
  sub: string;
  email: string;
  type: 'password_reset';
  tokenVersion: number;
}

@Injectable()
export class AuthTokenService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async generateRefreshToken(user: UserResponseDto): Promise<string> {
    const tokenVersion =
      (await this.usersService.getRefreshTokenVersion(user._id)) ?? 0;
    return this.jwtService.signAsync(
      {
        sub: user._id,
        type: 'refresh',
        tokenVersion,
        role: user.role,
      },
      {
        secret: this.requireSecret('JWT_REFRESH_SECRET'),
        expiresIn: this.getExpiration('JWT_REFRESH_EXPIRED', '7d'),
      },
    );
  }

  async generateAccessToken(
    user: UserResponseDto,
    refreshToken: string,
    tokenVersion: number | undefined,
  ): Promise<string> {
    const storedUser = await this.usersService.findUserById(user._id);
    if (!storedUser) throw new BadRequestException('User does not exist');

    const storedRefreshToken = await this.usersService.getRefreshToken(
      user._id,
    );
    if (!(await comparePassword(refreshToken, storedRefreshToken))) {
      throw new UnauthorizedException('Refresh token invalid');
    }

    const currentVersion = await this.usersService.getRefreshTokenVersion(
      user._id,
    );
    if (currentVersion !== tokenVersion) {
      throw new UnauthorizedException('Refresh token invalid');
    }

    return this.jwtService.signAsync({
      sub: user._id,
      email: storedUser.email,
      type: 'accessToken',
      role: storedUser.role,
      tokenVersion: currentVersion,
    });
  }

  generateEmailVerificationToken(userId: string, jti: string): Promise<string> {
    return this.jwtService.signAsync(
      { sub: userId, type: 'email_verify', jti },
      {
        secret: this.requireSecret('JWT_EMAIL_VERIFY_SECRET'),
        expiresIn: this.getExpiration('JWT_EMAIL_VERIFY_EXPIRE', '15m'),
      },
    );
  }

  async verifyEmailVerificationToken(
    token: string,
  ): Promise<EmailVerificationPayload> {
    try {
      return await this.jwtService.verifyAsync<EmailVerificationPayload>(
        token,
        {
          secret: this.requireSecret('JWT_EMAIL_VERIFY_SECRET'),
        },
      );
    } catch {
      throw new BadRequestException('Invalid or expired token');
    }
  }

  async generateResetPasswordToken(
    userId: string,
    email: string,
  ): Promise<string> {
    const tokenVersion =
      (await this.usersService.getRefreshTokenVersion(userId)) ?? 0;
    return this.jwtService.signAsync(
      { sub: userId, email, type: 'password_reset', tokenVersion },
      {
        secret: this.getResetPasswordSecret(),
        expiresIn: this.getExpiration('JWT_RESET_PASSWORD_EXPIRE', '10m'),
      },
    );
  }

  async verifyResetPasswordToken(token: string): Promise<ResetPasswordPayload> {
    try {
      return await this.jwtService.verifyAsync<ResetPasswordPayload>(token, {
        secret: this.getResetPasswordSecret(),
      });
    } catch {
      throw new BadRequestException(
        'Reset token không hợp lệ hoặc đã hết hạn.',
      );
    }
  }

  private getResetPasswordSecret(): string {
    return (
      this.configService.get<string>('JWT_RESET_PASSWORD_SECRET') ??
      this.requireSecret('JWT_ACCESS_SECRET')
    );
  }

  private requireSecret(key: string): string {
    const secret = this.configService.get<string>(key);
    if (!secret) {
      throw new InternalServerErrorException(`${key} is not configured`);
    }
    return secret;
  }

  private getExpiration(
    key: string,
    fallback?: SignOptions['expiresIn'],
  ): SignOptions['expiresIn'] {
    return (
      (this.configService.get<string>(key) as SignOptions['expiresIn']) ??
      fallback
    );
  }
}
