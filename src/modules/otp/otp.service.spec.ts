import { hashPassword } from '@/common/helpers/password.helpers';
import type { OtpDocument } from '@/modules/otp/schemas/otp.schema';
import { OtpRepository } from './otp.repository';
import { OtpService } from './otp.service';

describe('OtpService', () => {
  let repository: jest.Mocked<OtpRepository>;
  let service: OtpService;

  beforeEach(() => {
    repository = {
      create: jest.fn(),
      deleteMany: jest.fn(),
      findLatestActive: jest.fn(),
      findOneAndUpdate: jest.fn(),
    } as unknown as jest.Mocked<OtpRepository>;
    service = new OtpService(repository);
  });

  it('hashes the OTP and invalidates older codes before storing it', async () => {
    repository.deleteMany.mockResolvedValue({
      acknowledged: true,
      deletedCount: 1,
    });
    repository.create.mockImplementation((data: unknown) =>
      Promise.resolve(data as OtpDocument),
    );

    const created = await service.createOtp({
      userId: 'user-id',
      purpose: 'forgot_password',
      otpCode: '123456',
      expiresInMinutes: 5,
    });

    expect(repository.deleteMany.mock.calls[0][0]).toEqual({
      userId: 'user-id',
      purpose: 'forgot_password',
      used: false,
    });
    expect(created.otpCode).not.toBe('123456');
  });

  it('consumes a valid OTP only once', async () => {
    const storedOtp = {
      _id: 'otp-id',
      userId: 'user-id',
      purpose: 'forgot_password',
      otpCode: await hashPassword('123456'),
      used: false,
      otpExpiresAt: new Date(Date.now() + 60_000),
    } as unknown as OtpDocument;
    repository.findLatestActive.mockResolvedValue(storedOtp);
    repository.findOneAndUpdate.mockResolvedValue(storedOtp);

    await expect(
      service.verifyOtp({
        userId: 'user-id',
        purpose: 'forgot_password',
        otpCode: '123456',
      }),
    ).resolves.toBe(true);
    expect(repository.findOneAndUpdate.mock.calls[0]).toEqual([
      { _id: 'otp-id', used: false },
      { $set: { used: true } },
    ]);
  });

  it('rejects an invalid OTP without consuming it', async () => {
    repository.findLatestActive.mockResolvedValue({
      otpCode: await hashPassword('123456'),
    } as OtpDocument);

    await expect(
      service.verifyOtp({
        userId: 'user-id',
        purpose: 'forgot_password',
        otpCode: '654321',
      }),
    ).resolves.toBe(false);
    expect(repository.findOneAndUpdate.mock.calls).toHaveLength(0);
  });
});
