import {
  BadGatewayException,
  BadRequestException,
  Injectable,
} from '@nestjs/common';
import { Model } from 'mongoose';
import { User } from 'src/modules/users/schemas/user.schema';
import { InjectModel } from '@nestjs/mongoose';
import { CreateUserDto } from 'src/modules/users/dto/create-user.dto';
import { hashPasswordHelper } from '@/common/helpers/ulti';
import { UpdateUserDto } from '@/modules/users/dto/update-user.dto';
import { ResetPasswordDto } from '@/modules/users/dto/reset-password.user.Dto';
import { UserDocument } from '@/common/types/user.types';
import { UserResponseDto } from '@/modules/users/dto/user-response.dto';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  async findUserByEmail(email: string): Promise<UserDocument | null> {
    try {
      const user = await this.userModel.findOne({ email }).lean();
      if (!user) return null;
      return user;
    } catch (error) {
      throw new BadRequestException();
    }
  }

  isEmailExist = async (email: string): Promise<boolean> => {
    try {
      const user = await this.userModel.exists({ email });
      return !!user; // convert undefined/null -> false
    } catch (error) {
      console.error('Error checking email existence:', error);
      throw new BadGatewayException('Lỗi kiểm tra email');
    }
  };

  isUserNameExist = async (username: string): Promise<boolean> => {
    try {
      const user = await this.userModel.exists({ username });
      return !!user;
    } catch (error) {
      console.error('Error checking username existence:', error);
      throw new BadGatewayException('Lỗi kiểm tra username');
    }
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
      lastLogin,
      ...result
    } = user.toObject ? user.toObject() : user;
    return result;
  }
  async resetPassword(data: ResetPasswordDto): Promise<boolean> {
    const { email, password } = data;
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
  async addRefreshTokenToDB(token: string, email: string) {
    const isExist = await this.findUserByEmail(email);
    if (!isExist) throw new BadRequestException();
    const user = await this.userModel.findOneAndUpdate(
      { email },
      { $set: { refreshToken: token } },
      { new: true },
    );
    if (!user) return false;
    return true;
  }
  async checkRefreshToken(user: UserDocument): Promise<boolean> {
    const userCheck = await this.findUserByEmail(user.email);
    if (!userCheck?.refreshToken) {
      return false;
    }
    return true;
  }
  async banUser(email: string): Promise<boolean> {
    const setBanUser = await this.userModel.findOneAndUpdate(
      { email },
      { $set: { isBanned: true } },
    );
    if (!setBanUser) return false;
    return true;
  }
  async generateOpt(user: UserDocument) {
    const code = uuidv4();
    const generateOpt = await this.userModel.findOneAndUpdate(
      { email: user.email },
      { $set: { otpCode: code, otpExpiresAt: new Date() } },
      { new: true },
    );
    if (!generateOpt) throw new BadGatewayException();
    return code;
  }

  async checkOtpCode(data: UserDocument, otpClient: string): Promise<boolean> {
    const user = await this.findUserByEmail(data.email);
    if (!user) throw new BadRequestException();
    const { otpCode, otpExpiresAt } = user;
    const nowDate = new Date();
    if (otpExpiresAt !== nowDate)
      throw new BadRequestException('otp code đã hết hạn vui lòng thử lại');
    if (otpClient !== otpCode) return false;
    return true;
  }
}
