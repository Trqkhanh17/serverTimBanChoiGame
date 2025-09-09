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
import { v4 as uuidv4 } from 'uuid';
@Injectable()
export class OtpService {
  constructor(@InjectModel(Otp.name) private otpModel: Model<OtpDocument>) {}

  // Tạo OTP mới
  async createOtp(otpInput: CreateOtpInput) {
    try {
      const { expiresInMinutes, purpose, userId } = otpInput;
      const otpCode = uuidv4();
      const otp = new this.otpModel({
        userId,
        otpCode,
        purpose,
        otpExpiresAt: new Date(Date.now() + expiresInMinutes * 60000),
      });
      return otp.save();
    } catch (error) {
      throw new BadRequestException();
    }
  }

  // Verify OTP
  async verifyOtp(input: verifyOtpInput) {
    try {
      const { otpCode, purpose, userId } = input;
      const otp = await this.otpModel.findOne({
        userId,
        otpCode,
        purpose,
        used: false,
        otpExpiresAt: { $gt: new Date() },
      });

      if (!otp) return false;

      otp.used = true;
      await otp.save();
      return true;
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException();
    }
  }

  // Xóa OTP hết hạn (cleanup, optional)
  async deleteExpiredOtps() {
    await this.otpModel.deleteMany({ otpExpiresAt: { $lt: new Date() } });
  }
}
