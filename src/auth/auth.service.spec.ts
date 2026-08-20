import { BadRequestException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthTokenService } from './services/auth-token.service';
import { EmailVerificationService } from './services/email-verification.service';
import { UsersService } from '@/modules/users/users.service';
import type { UserDocument } from '@/modules/users/schemas/user.schema';
import type { UserResponseDto } from '@/modules/users/dto/user-response.dto';

describe('AuthService', () => {
  const userId = '507f1f77bcf86cd799439011';
  const user = {
    _id: userId,
    email: 'user@example.com',
    username: 'test_user',
    name: 'Test User',
    isActive: false,
    isBanned: false,
    refreshTokenVersion: 0,
    role: 'user',
  } as unknown as UserDocument;
  const userResponse = {
    ...user,
    _id: userId,
  } as unknown as UserResponseDto;

  let service: AuthService;
  let usersService: jest.Mocked<UsersService>;
  let tokenService: jest.Mocked<AuthTokenService>;
  let emailVerificationService: jest.Mocked<EmailVerificationService>;

  beforeEach(() => {
    usersService = {
      isEmailExist: jest.fn(),
      isUserNameExist: jest.fn(),
      createUser: jest.fn(),
      addRefreshTokenToDB: jest.fn(),
      getRefreshTokenVersion: jest.fn(),
      checkPassword: jest.fn(),
      changeUserPassword: jest.fn(),
      revokeAllRefreshTokens: jest.fn(),
    } as unknown as jest.Mocked<UsersService>;
    tokenService = {
      generateRefreshToken: jest.fn(),
      generateAccessToken: jest.fn(),
    } as unknown as jest.Mocked<AuthTokenService>;
    emailVerificationService = {
      send: jest.fn(),
    } as unknown as jest.Mocked<EmailVerificationService>;

    service = new AuthService(
      usersService,
      tokenService,
      emailVerificationService,
    );
  });

  it('registers an inactive account without issuing auth tokens', async () => {
    usersService.isEmailExist.mockResolvedValue(false);
    usersService.isUserNameExist.mockResolvedValue(false);
    usersService.createUser.mockResolvedValue(user);

    const result = await service.register({
      email: 'USER@example.com',
      username: 'test_user',
      password: 'Password123',
      name: 'Test User',
    });

    expect(result.user).toMatchObject({
      email: 'user@example.com',
      isActive: false,
    });
    expect(result).not.toHaveProperty('access_token');
    expect(result).not.toHaveProperty('refresh_token');
    expect(emailVerificationService.send.mock.calls).toEqual([[result.user]]);
  });

  it('creates and persists refresh and access tokens on login', async () => {
    tokenService.generateRefreshToken.mockResolvedValue('refresh-token');
    usersService.addRefreshTokenToDB.mockResolvedValue(true);
    usersService.getRefreshTokenVersion.mockResolvedValue(0);
    tokenService.generateAccessToken.mockResolvedValue('access-token');

    await expect(service.login(userResponse)).resolves.toMatchObject({
      access_token: 'access-token',
      refresh_token: 'refresh-token',
      user: { email: userResponse.email },
    });
    expect(usersService.addRefreshTokenToDB.mock.calls).toEqual([
      ['refresh-token', userId],
    ]);
  });

  it('rejects an incorrect current password', async () => {
    usersService.checkPassword.mockResolvedValue(false);

    await expect(
      service.changePassword({
        userId,
        oldPassword: 'wrong-password',
        newPassword: 'NewPassword123',
        confirmPassword: 'NewPassword123',
      }),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(usersService.changeUserPassword.mock.calls).toHaveLength(0);
  });
});
