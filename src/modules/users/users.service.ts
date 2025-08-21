import {
  BadRequestException,
  HttpException,
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
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

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  async findUserByEmail(email: string): Promise<UserDocument | null> {
    try {
      const user = await this.userModel.findOne({ email }).lean();
      return user || null;
    } catch (error) {
      this.logger.error(
        `Database error finding user by email: ${email}`,
        error.stack,
      );
      throw new InternalServerErrorException('Database query failed');
    }
  }

  async isEmailExist(email: string): Promise<boolean> {
    try {
      const user = await this.userModel.exists({ email });
      return !!user;
    } catch (error) {
      this.logger.error(
        `Database error checking email existence: ${email}`,
        error.stack,
      );
      throw new InternalServerErrorException('Database query failed');
    }
  }

  async isUserNameExist(username: string): Promise<boolean> {
    try {
      const user = await this.userModel.exists({ username });
      return !!user;
    } catch (error) {
      this.logger.error(
        `Database error checking username existence: ${username}`,
        error.stack,
      );
      throw new InternalServerErrorException('Database query failed');
    }
  }

  async createUser(body: CreateUserDto): Promise<UserDocument> {
    try {
      const { email, password, username, name } = body;
      const hashPassword = await hashPasswordHelper(password);

      const user = await this.userModel.create({
        email,
        password: hashPassword,
        username,
        name,
      });

      this.logger.log(`User created successfully: ${email}`);
      return user;
    } catch (error) {
      this.logger.error('Database error creating user', error.stack);
      throw new InternalServerErrorException(
        'Failed to create user in database',
      );
    }
  }

  async getProfileUser(email: string): Promise<UserResponseDto | null> {
    try {
      const user = await this.findUserByEmail(email);
      if (!user) return null;

      const result: UserResponseDto = {
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
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      this.logger.error(`Error getting user profile: ${email}`, error.stack);
      throw new InternalServerErrorException('Failed to retrieve user profile');
    }
  }

  async findUserById(_id: string): Promise<UserDocument | null> {
    try {
      const user = await this.userModel.findOne({ _id }).lean();
      return user || null;
    } catch (error) {
      this.logger.error(
        `Database error finding user by ID: ${_id}`,
        error.stack,
      );
      throw new InternalServerErrorException('Database query failed');
    }
  }

  async updateUserProfile(email: string, body: UpdateUserDto) {
    try {
      const user = await this.userModel.findOneAndUpdate(
        { email },
        { $set: body },
        { new: true },
      );

      if (!user) return null;

      const { password, _id, authProvider, lastLogin, ...result } =
        user.toObject ? user.toObject() : user;

      this.logger.log(`User profile updated: ${email}`);
      return result;
    } catch (error) {
      this.logger.error(
        `Database error updating user profile: ${email}`,
        error.stack,
      );
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Failed to update user profile');
    }
  }

  async resetPassword(data: ResetPasswordDto): Promise<boolean> {
    try {
      const { email, password } = data;
      const hashedPass = await hashPasswordHelper(password);

      const updatedUser = await this.userModel.findOneAndUpdate(
        { email },
        { $set: { password: hashedPass } },
        { new: true },
      );

      if (!updatedUser) return false;

      this.logger.log(`Password reset successfully: ${email}`);
      return true;
    } catch (error) {
      this.logger.error(
        `Database error resetting password: ${data?.email}`,
        error.stack,
      );
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Failed to reset password');
    }
  }

  async addRefreshTokenToDB(token: string, email: string): Promise<boolean> {
    try {
      const user = await this.userModel.findOneAndUpdate(
        { email },
        { $set: { refreshToken: token } },
        { new: true },
      );

      return !!user;
    } catch (error) {
      this.logger.error(
        `Database error adding refresh token: ${email}`,
        error.stack,
      );
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Failed to save refresh token');
    }
  }

  async getRefreshToken(_id: string): Promise<string | null> {
    try {
      const user = await this.userModel
        .findOne({ _id, refreshToken: { $exists: true, $ne: null } })
        .lean();
      return user?.refreshToken ? user.refreshToken : null;
    } catch (error) {
      this.logger.error(
        `Database error checking refresh token: ${_id}`,
        error.stack,
      );
      throw new InternalServerErrorException('Database query failed');
    }
  }

  async banUser(email: string): Promise<boolean> {
    try {
      const result = await this.userModel.findOneAndUpdate(
        { email },
        { $set: { isBanned: true } },
        { new: true },
      );

      if (!result) return false;

      this.logger.log(`User banned: ${email}`);
      return true;
    } catch (error) {
      this.logger.error(`Database error banning user: ${email}`, error.stack);
      throw new InternalServerErrorException('Failed to ban user');
    }
  }

  async removeRefreshToken(_id: string): Promise<boolean> {
    try {
      const checkRefreshToken = await this.getRefreshToken(_id);
      if (!checkRefreshToken) throw new UnauthorizedException();
      const result = await this.userModel.updateOne(
        { _id },
        { $unset: { refreshToken: '' } },
      );

      this.logger.log(`Refresh token removed for user: ${_id}`);
      return result.modifiedCount > 0;
    } catch (error) {
      this.logger.error(
        `Database error removing refresh token: ${_id}`,
        error.stack,
      );
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Failed to remove refresh token');
    }
  }

  async getUserStats(): Promise<{
    totalUsers: number;
    activeUsers: number;
    bannedUsers: number;
  }> {
    try {
      const [totalUsers, activeUsers, bannedUsers] = await Promise.all([
        this.userModel.countDocuments(),
        this.userModel.countDocuments({ isActive: true }),
        this.userModel.countDocuments({ isBanned: true }),
      ]);

      return { totalUsers, activeUsers, bannedUsers };
    } catch (error) {
      this.logger.error('Database error getting user stats', error.stack);
      throw new InternalServerErrorException('Failed to get user statistics');
    }
  }

  async findUsersByIds(userIds: string[]): Promise<UserDocument[]> {
    try {
      const users = await this.userModel.find({ _id: { $in: userIds } }).lean();
      return users;
    } catch (error) {
      this.logger.error('Database error finding users by IDs', error.stack);
      throw new InternalServerErrorException('Database query failed');
    }
  }
}
