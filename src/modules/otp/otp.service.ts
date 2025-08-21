import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Otp, OtpDocument, OtpPurpose } from '@/modules/otp/schemas/otp.schema';
import { Model } from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
@Injectable()
export class OtpService {
  constructor(@InjectModel(Otp.name) private otpModel: Model<OtpDocument>) {}

  // Tạo OTP mới
  async createOtp(
    userId: string,
    purpose: OtpPurpose,
    expiresInMinutes: number,
  ) {
    const otpCode = await uuidv4();
    const otp = new this.otpModel({
      userId,
      otpCode,
      purpose,
      otpExpiresAt: new Date(Date.now() + expiresInMinutes * 60000),
    });
    return otp.save();
  }

  // Verify OTP
  async verifyOtp(userId: string, otpCode: string, purpose: OtpPurpose) {
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
  }

  // Xóa OTP hết hạn (cleanup, optional)
  async deleteExpiredOtps() {
    await this.otpModel.deleteMany({ otpExpiresAt: { $lt: new Date() } });
  }
}
