import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { AbstractRepository } from '@/common/repositories/abstract.repository';
import { User } from '@/modules/users/schemas/user.schema';
import { UserDocument } from '@/common/types/user.types';

@Injectable()
export class UsersRepository extends AbstractRepository<UserDocument> {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
  ) {
    super(userModel);
  }

  async findByEmailWithPassword(email: string): Promise<UserDocument | null> {
    return this.userModel
      .findOne({ email })
      .select('+password')
      .lean<UserDocument>()
      .exec();
  }
}
