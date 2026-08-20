import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import {
  ChangePasswordInput,
  CheckPasswordInput,
  UserCreateInput,
  UserUpdateInput,
} from '@/common/types/user.types';
import {
  comparePassword,
  hashPassword,
} from '@/common/helpers/password.helpers';
import { UserResponseDto } from './dto/user-response.dto';
import { UsersRepository } from './users.repository';
import type { UserDocument } from './schemas/user.schema';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(private readonly usersRepository: UsersRepository) {}

  findByEmailForAuth(email: string): Promise<UserDocument | null> {
    return this.usersRepository.findByEmailWithPassword(
      this.normalizeEmail(email),
    );
  }

  findUserByEmail(email: string): Promise<UserDocument | null> {
    return this.usersRepository.findOne({ email: this.normalizeEmail(email) });
  }

  isEmailExist(email: string): Promise<boolean> {
    return this.usersRepository.exists({ email: this.normalizeEmail(email) });
  }

  isUserNameExist(username: string): Promise<boolean> {
    return this.usersRepository.exists({ username });
  }

  async createUser(input: UserCreateInput): Promise<UserDocument> {
    const user = await this.usersRepository.create({
      email: this.normalizeEmail(input.email),
      password: input.passwordHash,
      username: input.username,
      name: input.name,
    });
    this.logger.log(`User created successfully: ${user.email}`);
    return user;
  }

  async getProfileUser(userId: string): Promise<UserResponseDto | null> {
    const user = await this.findUserById(userId);
    return user ? this.toResponse(user) : null;
  }

  findUserById(userId: string): Promise<UserDocument | null> {
    return this.usersRepository.findById(userId);
  }

  async updateUserProfile(
    userId: string,
    data: UserUpdateInput,
  ): Promise<UserResponseDto | null> {
    const user = await this.usersRepository.findByIdAndUpdate(userId, {
      $set: data,
    });
    if (!user) return null;

    this.logger.log(`User profile updated: ${userId}`);
    return this.toResponse(user);
  }

  async checkPassword(input: CheckPasswordInput): Promise<boolean> {
    const user = await this.usersRepository.findByIdWithPassword(input.userId);
    return comparePassword(input.password, user?.password);
  }

  async changeUserPassword(input: ChangePasswordInput): Promise<boolean> {
    const password = await hashPassword(input.newPassword);
    const user = await this.usersRepository.findOneAndUpdate(
      { _id: input.userId },
      { $set: { password } },
    );
    if (!user) return false;

    this.logger.log(`Password changed successfully: ${input.userId}`);
    return true;
  }

  async addRefreshTokenToDB(token: string, userId: string): Promise<boolean> {
    const refreshToken = await hashPassword(token);
    const user = await this.usersRepository.findOneAndUpdate(
      { _id: userId },
      { $set: { refreshToken } },
    );
    return Boolean(user);
  }

  async getRefreshToken(userId: string): Promise<string | null> {
    const user = await this.usersRepository.findOne(
      { _id: userId, refreshToken: { $exists: true, $ne: null } },
      'refreshToken',
    );
    return user?.refreshToken ?? null;
  }

  async getRefreshTokenVersion(userId: string): Promise<number | null> {
    const user = await this.usersRepository.findOne(
      { _id: userId },
      { refreshTokenVersion: 1, _id: 0 },
    );
    return user?.refreshTokenVersion ?? null;
  }

  async banUser(email: string): Promise<boolean> {
    const user = await this.usersRepository.findOneAndUpdate(
      { email: this.normalizeEmail(email) },
      { $set: { isBanned: true } },
    );
    if (!user) return false;

    this.logger.log(`User banned: ${email}`);
    return true;
  }

  async removeRefreshToken(userId: string): Promise<boolean> {
    const result = await this.usersRepository.updateOne(
      { _id: userId, refreshToken: { $exists: true, $ne: null } },
      {
        $unset: { refreshToken: '' },
        $inc: { refreshTokenVersion: 1 },
      },
    );
    if (result.modifiedCount === 0) {
      throw new UnauthorizedException('Refresh token not found');
    }

    this.logger.log(`Refresh token removed for user: ${userId}`);
    return true;
  }

  async revokeAllRefreshTokens(userId: string): Promise<void> {
    await this.usersRepository.updateOne(
      { _id: userId },
      {
        $unset: { refreshToken: '' },
        $inc: { refreshTokenVersion: 1 },
      },
    );
  }

  async getUserStats(): Promise<{
    totalUsers: number;
    activeUsers: number;
    bannedUsers: number;
  }> {
    const [totalUsers, activeUsers, bannedUsers] = await Promise.all([
      this.usersRepository.countDocuments(),
      this.usersRepository.countDocuments({ isActive: true }),
      this.usersRepository.countDocuments({ isBanned: true }),
    ]);
    return { totalUsers, activeUsers, bannedUsers };
  }

  findUsersById(userIds: string[]): Promise<UserDocument[]> {
    return this.usersRepository.find({ _id: { $in: userIds } });
  }

  async setVerifyJti(userId: string, jti: string): Promise<boolean> {
    const verifyJti = await hashPassword(jti);
    const result = await this.usersRepository.updateOne(
      { _id: userId },
      { $set: { verifyJti } },
    );
    return result.matchedCount > 0;
  }

  async consumeVerifyJti(userId: string, jti: string): Promise<boolean> {
    const user = await this.findUserById(userId);
    if (!user?.verifyJti || !(await comparePassword(jti, user.verifyJti))) {
      return false;
    }

    const result = await this.usersRepository.updateOne(
      { _id: userId, isActive: false, verifyJti: user.verifyJti },
      {
        $set: { isActive: true, emailVerifiedAt: new Date(), verifyJti: null },
      },
    );
    return result.modifiedCount > 0;
  }

  private normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
  }

  private toResponse(user: UserDocument): UserResponseDto {
    return {
      _id: user._id.toString(),
      email: user.email,
      username: user.username,
      name: user.name,
      isActive: user.isActive,
      isBanned: user.isBanned,
      role: user.role,
      bio: user.bio,
      gender: user.gender,
      birthDate: user.birthDate,
      avatarUrl: user.avatarUrl,
    };
  }
}
