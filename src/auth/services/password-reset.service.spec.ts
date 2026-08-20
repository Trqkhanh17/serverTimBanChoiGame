import { BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MailService } from '@/mail/mail.service';
import { OtpService } from '@/modules/otp/otp.service';
import { UsersService } from '@/modules/users/users.service';
import type { UserDocument } from '@/modules/users/schemas/user.schema';
import { AuthTokenService } from './auth-token.service';
import { PasswordResetService } from './password-reset.service';

describe('PasswordResetService', () => {
  const userId = '507f1f77bcf86cd799439011';
  const user = {
    _id: userId,
    email: 'user@example.com',
    name: 'Test User',
  } as unknown as UserDocument;

  let service: PasswordResetService;
  let usersService: jest.Mocked<UsersService>;
  let otpService: jest.Mocked<OtpService>;
  let tokenService: jest.Mocked<AuthTokenService>;

  beforeEach(() => {
    usersService = {
      findUserByEmail: jest.fn(),
      getRefreshTokenVersion: jest.fn(),
      changeUserPassword: jest.fn(),
      revokeAllRefreshTokens: jest.fn(),
    } as unknown as jest.Mocked<UsersService>;
    otpService = {
      createOtp: jest.fn(),
      verifyOtp: jest.fn(),
    } as unknown as jest.Mocked<OtpService>;
    tokenService = {
      generateResetPasswordToken: jest.fn(),
      verifyResetPasswordToken: jest.fn(),
    } as unknown as jest.Mocked<AuthTokenService>;
    const mailService = {
      sendOtpForgotPassword: jest.fn(),
    } as unknown as jest.Mocked<MailService>;
    const configService = {
      get: jest.fn(),
    } as unknown as ConfigService;

    service = new PasswordResetService(
      usersService,
      otpService,
      mailService,
      tokenService,
      configService,
    );
  });

  it('returns a reset token only after a valid OTP', async () => {
    usersService.findUserByEmail.mockResolvedValue(user);
    otpService.verifyOtp.mockResolvedValue(true);
    tokenService.generateResetPasswordToken.mockResolvedValue('reset-token');

    await expect(
      service.verifyOtp('user@example.com', '123456'),
    ).resolves.toEqual({ reset_token: 'reset-token' });
    expect(otpService.verifyOtp.mock.calls).toEqual([
      [
        {
          userId,
          otpCode: '123456',
          purpose: 'forgot_password',
        },
      ],
    ]);
  });

  it('rejects an invalid or expired OTP', async () => {
    usersService.findUserByEmail.mockResolvedValue(user);
    otpService.verifyOtp.mockResolvedValue(false);

    await expect(
      service.verifyOtp('user@example.com', '000000'),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('changes a forgotten password and revokes every existing token', async () => {
    tokenService.verifyResetPasswordToken.mockResolvedValue({
      sub: userId,
      email: user.email,
      type: 'password_reset',
      tokenVersion: 0,
    });
    usersService.getRefreshTokenVersion.mockResolvedValue(0);
    usersService.changeUserPassword.mockResolvedValue(true);

    await expect(
      service.reset({
        resetToken: 'valid-token',
        newPassword: 'NewPassword123',
        confirmPassword: 'NewPassword123',
      }),
    ).resolves.toEqual({ message: 'Password changed successfully' });
    expect(usersService.changeUserPassword.mock.calls).toEqual([
      [{ userId, newPassword: 'NewPassword123' }],
    ]);
    expect(usersService.revokeAllRefreshTokens.mock.calls).toEqual([[userId]]);
  });

  it('rejects reuse of a reset token after its version is revoked', async () => {
    tokenService.verifyResetPasswordToken.mockResolvedValue({
      sub: userId,
      email: user.email,
      type: 'password_reset',
      tokenVersion: 0,
    });
    usersService.getRefreshTokenVersion.mockResolvedValue(1);

    await expect(
      service.reset({
        resetToken: 'used-token',
        newPassword: 'NewPassword123',
        confirmPassword: 'NewPassword123',
      }),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(usersService.changeUserPassword.mock.calls).toHaveLength(0);
  });
});
