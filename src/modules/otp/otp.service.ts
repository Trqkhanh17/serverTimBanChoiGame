import {
  comparePassword,
  hashPassword,
} from '@/common/helpers/password.helpers';
import { CreateOtpInput, VerifyOtpInput } from '@/common/types/otp.types';
import {
  BadRequestException,
  HttpException,
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { OtpRepository } from './otp.repository';
@Injectable()
export class OtpService {
  private readonly logger = new Logger(OtpService.name);

  constructor(private readonly otpRepository: OtpRepository) {}

  // Tạo OTP mới
  async createOtp(otpInput: CreateOtpInput) {
    try {
      const { expiresInMinutes, purpose, userId, otpCode } = otpInput;
      await this.otpRepository.deleteMany({ userId, purpose, used: false });
      const otpCodeHash = await hashPassword(otpCode);
      const otp = await this.otpRepository.create({
        userId,
        otpCode: otpCodeHash,
        purpose,
        otpExpiresAt: new Date(Date.now() + expiresInMinutes * 60000),
      });
      return otp;
    } catch (error: unknown) {
      this.logger.error('Unable to create OTP', error);
      throw new BadRequestException('Không thể tạo mã OTP.');
    }
  }

  // Verify OTP
  async verifyOtp(input: VerifyOtpInput): Promise<boolean> {
    try {
      const { otpCode, purpose, userId } = input;
      const otp = await this.otpRepository.findLatestActive(userId, purpose);
      if (!otp || !(await comparePassword(otpCode, otp.otpCode))) return false;

      const consumed = await this.otpRepository.findOneAndUpdate(
        { _id: otp._id, used: false },
        { $set: { used: true } },
      );
      return !!consumed;
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException();
    }
  }

  // Xóa OTP hết hạn (cleanup, optional)
  async deleteExpiredOtps() {
    await this.otpRepository.deleteMany({ otpExpiresAt: { $lt: new Date() } });
  }
}
