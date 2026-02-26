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
import {
  changePasswordInPut,
  checkPasswordInPut,
  UserCreateInput,
  UserDocument,
  UserUpdateInput,
} from '@/common/types/user.types';
import { UserResponseDto } from '@/modules/users/dto/user-response.dto';
import { compareHelper, hashHelper } from '@/common/helpers/ulti';

import { UsersRepository } from './users.repository';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(private readonly usersRepository: UsersRepository) {}

  async findByEmailForAuth(email: string): Promise<UserDocument | null> {
    try {
      const norm = email.trim().toLowerCase();
      const user = await this.usersRepository.findByEmailWithPassword(norm);
      return user || null;
    } catch (error) {
      this.logger.error(
        `Database error finding user by email: ${email}`,
        error.stack,
      );
      throw new InternalServerErrorException('Database query failed');
    }
  }

  async findUserByEmail(email: string): Promise<UserDocument | null> {
    try {
      const norm = email.trim().toLowerCase();
      const user = await this.usersRepository.findOne({ email: norm });
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
      const user = await this.usersRepository.exists({ email });
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
      const user = await this.usersRepository.exists({ username });
      return !!user;
    } catch (error) {
      this.logger.error(
        `Database error checking username existence: ${username}`,
        error.stack,
      );
      throw new InternalServerErrorException('Database query failed');
    }
  }

  async createUser(dataInput: UserCreateInput): Promise<UserDocument> {
    try {
      const { email, passwordHash, username, name } = dataInput;

      const user = await this.usersRepository.create({
        email,
        password: passwordHash,
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

  async getProfileUser(_id: string): Promise<UserResponseDto | null> {
    try {
      const user = await this.findUserById(_id);
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
      this.logger.error(`Error getting user profile: ${_id}`, error.stack);
      throw new InternalServerErrorException('Failed to retrieve user profile');
    }
  }

  async findUserById(userId: string): Promise<UserDocument | null> {
    try {
      const user = await this.usersRepository.findById(userId);
      return user || null;
    } catch (error) {
      this.logger.error(
        `Database error finding user by ID: ${userId}`,
        error.stack,
      );
      throw new InternalServerErrorException('Database query failed');
    }
  }

  async updateUserProfile(
    userId: string,
    data: UserUpdateInput,
  ): Promise<UserResponseDto | null> {
    try {
      const user = await this.usersRepository.findByIdAndUpdate(userId, {
        $set: data,
      });

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

      this.logger.log(`User profile updated: ${userId}`);
      return result;
    } catch (error) {
      this.logger.error(
        `Database error updating user profile: ${userId}`,
        error.stack,
      );
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Failed to update user profile');
    }
  }

  async checkPassword(
    checkPasswordInPut: checkPasswordInPut,
  ): Promise<boolean> {
    try {
      const { password, userId } = checkPasswordInPut;
      const user = await this.findUserById(userId);
      if (!user) throw new BadRequestException();
      const currentPassword = user.password;
      const isMatch = await compareHelper(password, currentPassword);
      if (!isMatch) return false;
      return true;
    } catch (error) {
      return false;
    }
  }
  async changeUserPassword(
    dataForChangePassword: changePasswordInPut,
  ): Promise<boolean> {
    try {
      const { userId, newPassword } = dataForChangePassword;

      const hashedPass = await hashHelper(newPassword);

      const updatedUser = await this.usersRepository.findOneAndUpdate(
        { _id: userId },
        { $set: { password: hashedPass } },
      );

      if (!updatedUser) return false;

      this.logger.log(`Password change successfully: ${userId}`);
      return true;
    } catch (error) {
      this.logger.error(
        `Database error change password: ${dataForChangePassword.userId}`,
        error.stack,
      );
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Failed to reset password');
    }
  }

  async addRefreshTokenToDB(token: string, userId: string): Promise<boolean> {
    try {
      const HashRefreshToken = await hashHelper(token);
      const user = await this.usersRepository.findOneAndUpdate(
        { _id: userId },
        { $set: { refreshToken: HashRefreshToken } },
      );

      return !!user;
    } catch (error) {
      this.logger.error(
        `Database error adding refresh token: ${userId}`,
        error.stack,
      );
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Failed to save refresh token');
    }
  }

  async getRefreshToken(_id: string): Promise<string | null> {
    try {
      const user = await this.usersRepository.findOne(
        { _id, refreshToken: { $exists: true, $ne: null } },
        'refreshToken',
      );
      return user?.refreshToken ? user.refreshToken : null;
    } catch (error) {
      this.logger.error(
        `Database error checking refresh token: ${_id}`,
        error.stack,
      );
      throw new InternalServerErrorException('Database query failed');
    }
  }

  async getRefreshTokenVersion(_id: string): Promise<number | null> {
    try {
      const user = await this.usersRepository.findOne(
        { _id },
        { refreshTokenVersion: 1, _id: 0 },
      );
      return user?.refreshTokenVersion ?? null;
    } catch (error) {
      this.logger.error(
        `Database error get RefreshTokenVersion: ${_id}`,
        error.stack,
      );
      throw new InternalServerErrorException('Database query failed');
    }
  }

  async banUser(email: string): Promise<boolean> {
    try {
      const result = await this.usersRepository.findOneAndUpdate(
        { email },
        { $set: { isBanned: true } },
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
      const result = await this.usersRepository.updateOne(
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
        this.usersRepository.countDocuments(),
        this.usersRepository.countDocuments({ isActive: true }),
        this.usersRepository.countDocuments({ isBanned: true }),
      ]);

      return { totalUsers, activeUsers, bannedUsers };
    } catch (error) {
      this.logger.error('Database error getting user stats', error.stack);
      throw new InternalServerErrorException('Failed to get user statistics');
    }
  }

  async findUsersById(userIds: string[]): Promise<UserDocument[]> {
    try {
      const users = await this.usersRepository.find({ _id: { $in: userIds } });
      return users;
    } catch (error) {
      this.logger.error('Database error finding users by IDs', error.stack);
      throw new InternalServerErrorException('Database query failed');
    }
  }
  async setVerifyJti(userId: string, jti: string): Promise<boolean> {
    const jtiHash = await hashHelper(jti);
    const user = await this.usersRepository.updateOne(
      { _id: userId },
      { $set: { verifyJti: jtiHash } },
    );
    if (!user) return false;
    return true;
  }
  async consumeVerifyJti(userId: string, jti: string): Promise<boolean> {
    const user = await this.findUserById(userId);
    if (!user || !user.verifyJti) return false;
    const isValid = await compareHelper(jti, user.verifyJti);
    if (!isValid) return false;
    const res = await this.usersRepository.updateOne(
      { _id: userId, isActive: false },
      {
        $set: { isActive: true, emailVerifiedAt: new Date(), verifyJti: null },
      },
    );
    return res.modifiedCount > 0;
  }
}
