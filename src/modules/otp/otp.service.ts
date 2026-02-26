import { hashHelper } from '@/common/helpers/ulti';
import {
  CreateOtpInput,
  OtpDocument,
  OtpPurpose,
  verifyOtpInput,
} from '@/common/types/opt.types';
import { Otp } from '@/modules/otp/schemas/otp.schema';
import {
  BadRequestException,
  HttpException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { OtpRepository } from './otp.repository';
@Injectable()
export class OtpService {
  constructor(private readonly otpRepository: OtpRepository) {}

  // Tạo OTP mới
  async createOtp(otpInput: CreateOtpInput) {
    try {
      const { expiresInMinutes, purpose, userId, otpCode } = otpInput;
      const OtpCodeHash = await hashHelper(otpCode);
      console.log(OtpCodeHash);
      const otp = await this.otpRepository.create({
        userId,
        otpCode: OtpCodeHash,
        purpose,
        otpExpiresAt: new Date(Date.now() + expiresInMinutes * 60000),
      });
      return otp;
    } catch (error) {
      throw new BadRequestException();
    }
  }

  // Verify OTP
  async verifyOtp(input: verifyOtpInput): Promise<boolean> {
    try {
      const { otpCode, purpose, userId } = input;
      const otp = await this.otpRepository.findOneAndUpdate(
        {
          userId,
          otpCode,
          purpose,
          used: false,
          otpExpiresAt: { $gt: new Date() },
        },
        { $set: { used: true } },
      );

      if (!otp) return false;

      return true;
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
