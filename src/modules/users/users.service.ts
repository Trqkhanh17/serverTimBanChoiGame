import { BadRequestException, Injectable } from '@nestjs/common';
import { Model } from 'mongoose';
import { User } from 'src/modules/users/schemas/user.schema';
import { InjectModel } from '@nestjs/mongoose';
import { CreateUserDto } from 'src/modules/users/dto/create-user.dto';
import { hashPasswordHelper } from '@/common/helpers/ulti';
import { UpdateUserDto } from '@/modules/users/dto/update-user.dto';
import { ResetPasswordDto } from '@/modules/users/dto/reset-password.user.Dto';
import { UserDocument } from '@/common/types/user.types';
import { UserResponseDto } from '@/modules/users/dto/user-response.dto';

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  async findUserByEmail(email: string): Promise<UserDocument | null> {
    const user = await this.userModel.findOne({ email }).lean();
    if (!user) return null;
    return user;
  }

  isEmailExist = async (email: string): Promise<boolean> => {
    const user = await this.userModel.exists({ email });
    if (user) return true;
    return false;
  };

  isUserNameExist = async (username: string): Promise<boolean> => {
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

  async getProfileUser(email: string): Promise<UserResponseDto | null> {
    const user = await this.findUserByEmail(email);
    if (!user) return null;
    const result = {
      _id: user._id.toString(),
      email: user.email,
      username: user.username,
      name: user.name,
      isActive: user.isActive,
      bio: user.bio,
      gender: user.gender,
      birthDate: user.birthDate,
      avatarUrl: user.avatarUrl,
    };
    return result;
  }

  async findUserById(_id: string) {
    const user = await this.userModel.findOne({ _id }).lean();
    if (!user) return null;
    return user;
  }

  async updateUserProfile(email: string, body: UpdateUserDto) {
    const userisExist = await this.findUserByEmail(email);
    if (!userisExist)
      throw new BadRequestException(
        `User có địa chỉ email ${email} không tồn tại`,
      );
    if (!body) throw new BadRequestException();
    const user = await this.userModel.findOneAndUpdate(
      { email },
      { $set: body },
      { new: true },
    );
    if (!user) throw new BadRequestException();
    const {
      password,
      _id,
      authProvider,
      otpCode,
      otpExpiresAt,
      resetPasswordExpires,
      lastLogin,
      ...result
    } = user.toObject ? user.toObject() : user;
    return result;
  }
  async resetPassword(
    email: string,
    { password }: ResetPasswordDto,
  ): Promise<boolean> {
    const hashedPass = await hashPasswordHelper(password);
    const updatedUser = await this.userModel.findOneAndUpdate(
      { email },
      { $set: { password: hashedPass } },
      { new: true },
    );

    if (!updatedUser) {
      return false;
    }
    return true;
  }
  async checkRefreshToken() {}
}
