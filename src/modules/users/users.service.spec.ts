import { UnauthorizedException } from '@nestjs/common';
import { UsersRepository } from './users.repository';
import { UsersService } from './users.service';
import type { UserDocument } from './schemas/user.schema';
import { hashPassword } from '@/common/helpers/password.helpers';

describe('UsersService', () => {
  let service: UsersService;
  let repository: jest.Mocked<UsersRepository>;

  beforeEach(() => {
    repository = {
      findOne: jest.fn(),
      findById: jest.fn(),
      findByIdWithPassword: jest.fn(),
      updateOne: jest.fn(),
    } as unknown as jest.Mocked<UsersRepository>;
    service = new UsersService(repository);
  });

  it('normalizes email before looking up a user', async () => {
    repository.findOne.mockResolvedValue(null);

    await service.findUserByEmail('  USER@Example.COM ');

    expect(repository.findOne.mock.calls).toEqual([
      [{ email: 'user@example.com' }],
    ]);
  });

  it('returns false when the supplied password is incorrect', async () => {
    repository.findByIdWithPassword.mockResolvedValue({
      password: await hashPassword('CorrectPassword123'),
    } as UserDocument);

    await expect(
      service.checkPassword({ userId: 'user-id', password: 'wrong-password' }),
    ).resolves.toBe(false);
  });

  it('does not report verification token persistence when user is absent', async () => {
    repository.updateOne.mockResolvedValue({
      acknowledged: true,
      matchedCount: 0,
      modifiedCount: 0,
      upsertedCount: 0,
      upsertedId: null,
    });

    await expect(service.setVerifyJti('missing-user', 'jti')).resolves.toBe(
      false,
    );
  });

  it('rejects logout when no stored refresh token was removed', async () => {
    repository.updateOne.mockResolvedValue({
      acknowledged: true,
      matchedCount: 0,
      modifiedCount: 0,
      upsertedCount: 0,
      upsertedId: null,
    });

    await expect(service.removeRefreshToken('user-id')).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });
});
