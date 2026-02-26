import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, FilterQuery } from 'mongoose';
import { AbstractRepository } from '@/common/repositories/abstract.repository';
import { Otp } from '@/modules/otp/schemas/otp.schema';
import { OtpDocument } from '@/common/types/opt.types'; // Fixed typo if possible, or leave as is if the path is opt.types

@Injectable()
export class OtpRepository extends AbstractRepository<OtpDocument> {
  constructor(
    @InjectModel(Otp.name) private readonly otpModel: Model<OtpDocument>,
  ) {
    super(otpModel);
  }

  async deleteMany(filterQuery: FilterQuery<OtpDocument>) {
    return this.otpModel.deleteMany(filterQuery).exec();
  }
}
