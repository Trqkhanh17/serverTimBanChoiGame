import { BadRequestException, Injectable } from '@nestjs/common';
import { Model } from 'mongoose';
import { User, UserDocument } from 'src/modules/users/schemas/user.schema';
import { InjectModel } from '@nestjs/mongoose';
import { CreateUserDto } from 'src/modules/users/dto/create-user.dto';
import { hashPasswordHelper } from '@/helpers/ulti';

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  async findUserByEmail(email: string): Promise<UserDocument | null> {
    return await this.userModel.findOne({ email }).exec();
  }

  isEmailExist = async (email: string) => {
    const user = await this.userModel.exists({ email });
    if (user) return true;
    return false;
  };
  isUserNameExist = async (username: string) => {
    const user = await this.userModel.exists({ username });
    if (user) return true;
    return false;
  };
  async createUser(body: CreateUserDto): Promise<UserDocument> {
    const { email, password, username, name } = body;
    const isEmailExist = await this.isEmailExist(email);
    const hashPassword = await hashPasswordHelper(password);

    if (isEmailExist)
      throw new BadRequestException(
        `email ${email} đã tồn tại vui lòng chọn email khác`,
      );
    const isUserNameExist = await this.isUserNameExist(username);
    if (isUserNameExist)
      throw new BadRequestException(
        `Username ${username} đã tồn tại vui lòng chọn Username khác`,
      );
    const user = await this.userModel.create({
      email,
      password: hashPassword,
      username,
      name,
    });
    if (!user) throw new BadRequestException();
    return user;
  }
}
