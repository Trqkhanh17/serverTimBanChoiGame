import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, FilterQuery, DeleteResult } from 'mongoose';
import { BaseRepository } from '@/common/repositories/base.repository';
import { Otp, OtpDocument } from '@/modules/otp/schemas/otp.schema';

@Injectable()
export class OtpRepository extends BaseRepository<Otp> {
  constructor(@InjectModel(Otp.name) private readonly otpModel: Model<Otp>) {
    super(otpModel);
  }

  async deleteMany(filterQuery: FilterQuery<Otp>): Promise<DeleteResult> {
    return this.otpModel.deleteMany(filterQuery).exec();
  }

  async findLatestActive(
    userId: string,
    purpose: OtpDocument['purpose'],
  ): Promise<OtpDocument | null> {
    return this.otpModel
      .findOne({
        userId,
        purpose,
        used: false,
        otpExpiresAt: { $gt: new Date() },
      })
      .sort({ createdAt: -1 })
      .exec();
  }
}
