import { Module } from '@nestjs/common';
import { AuthService } from '@/auth/auth.service';
import { AuthController } from '@/auth/auth.controller';
import { UsersModule } from '@/modules/users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from '@/auth/passport/strategies/local.strategy';
import { JwtStrategy } from '@/auth/passport/strategies/jwt.access.strategy';
import { JwtRefreshStrategy } from '@/auth/passport/strategies/jwt-refresh.strategy';
import { OtpModule } from '@/modules/otp/otp.module';
import { MailModule } from '@/mail/mail.module';
import type { SignOptions } from 'jsonwebtoken';
import { AuthTokenService } from './services/auth-token.service';
import { EmailVerificationService } from './services/email-verification.service';
import { PasswordResetService } from './services/password-reset.service';

@Module({
  imports: [
    UsersModule,
    OtpModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        global: true,
        secret: configService.get<string>('JWT_ACCESS_SECRET'),
        signOptions: {
          expiresIn: (configService.get<string>('JWT_ACCESS_EXPIRED') ??
            '15m') as SignOptions['expiresIn'],
        },
      }),
    }),
    PassportModule,
    MailModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    AuthTokenService,
    EmailVerificationService,
    PasswordResetService,
    LocalStrategy,
    JwtStrategy,
    JwtRefreshStrategy,
  ],
  exports: [AuthService],
})
export class AuthModule {}
