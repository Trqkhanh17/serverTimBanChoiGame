import {
  BadRequestException,
  ConflictException,
  HttpException,
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { UpdateUserDto } from '@/auth/dto/update-user.dto';
import { AuthResponseDto } from '@/auth/dto/auth-response.dto';
import { RegisterDto } from '@/auth/dto/register-user.dto';
import { AuthUser, ChangeOwnPasswordInput } from '@/common/types/auth.types';
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
import { getErrorStack } from '@/common/helpers/error.helpers';
import { UserResponseDto } from '@/modules/users/dto/user-response.dto';
import { UsersService } from '@/modules/users/users.service';
import { AuthTokenService } from './services/auth-token.service';
import { EmailVerificationService } from './services/email-verification.service';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly usersService: UsersService,
    private readonly tokenService: AuthTokenService,
    private readonly emailVerificationService: EmailVerificationService,
  ) {}

  async validateUser(
    email: string,
    password: string,
  ): Promise<AuthUser | null> {
    const user = await this.usersService.findByEmailForAuth(email);
    if (!user || !(await comparePassword(password, user.password))) return null;

    return {
      _id: user._id.toString(),
      email: user.email.toLowerCase().trim(),
      username: user.username,
      name: user.name,
      isActive: user.isActive,
      isBanned: user.isBanned,
      role: user.role,
    };
  }

  async login(user: UserResponseDto): Promise<AuthResponseDto> {
    try {
      if (!user) throw new BadRequestException('User is required');

      const refreshToken = await this.tokenService.generateRefreshToken(user);
      const saved = await this.usersService.addRefreshTokenToDB(
        refreshToken,
        user._id,
      );
      if (!saved) {
        throw new InternalServerErrorException('Failed to save refresh token');
      }

      const tokenVersion = await this.usersService.getRefreshTokenVersion(
        user._id,
      );
      const accessToken = await this.tokenService.generateAccessToken(
        user,
        refreshToken,
        tokenVersion ?? undefined,
      );

      this.logger.log(`Login successful: ${user.email}`);
      return {
        message: 'Login successful',
        access_token: accessToken,
        refresh_token: refreshToken,
        user: this.toClientUser(user),
      };
    } catch (error: unknown) {
      if (error instanceof HttpException) throw error;
      this.logger.error(
        `Login failed for user ${user?.email}`,
        getErrorStack(error),
      );
      throw new InternalServerErrorException('Failed to login');
    }
  }

  async refresh(
    user: UserResponseDto,
    refreshToken: string,
  ): Promise<{ access_token: string }> {
    return {
      access_token: await this.tokenService.generateAccessToken(
        user,
        refreshToken,
        user.tokenVersion,
      ),
    };
  }

  async register(data: RegisterDto): Promise<{
    message: string;
    user: UserResponseDto;
  }> {
    try {
      const email = data.email.toLowerCase().trim();
      if (await this.usersService.isEmailExist(email)) {
        throw new ConflictException(
          `Email ${data.email} is already in use, please choose another one`,
        );
      }
      if (await this.usersService.isUserNameExist(data.username)) {
        throw new ConflictException(
          `Username ${data.username} is already in use, please choose another one`,
        );
      }

      const createInput: UserCreateInput = {
        email,
        passwordHash: await hashPassword(data.password),
        username: data.username,
        name: data.name,
      };
      const createdUser = await this.usersService.createUser(createInput);
      const user: UserResponseDto = {
        _id: createdUser._id.toString(),
        email: createdUser.email,
        name: createdUser.name,
        username: createdUser.username,
        isActive: createdUser.isActive,
      };

      this.logger.log(`Account created successfully: ${user.email}`);
      await this.emailVerificationService.send(user);
      return {
        message:
          'Account created successfully. Please verify your email before logging in.',
        user,
      };
    } catch (error: unknown) {
      if (error instanceof HttpException) throw error;
      this.logger.error(
        `Register error for ${data?.email}`,
        getErrorStack(error),
      );
      throw new InternalServerErrorException(
        'Failed to create user in database',
      );
    }
  }

  async getProfileUser(user: UserResponseDto): Promise<UserResponseDto> {
    const profile = await this.usersService.getProfileUser(user._id);
    if (!profile) {
      throw new BadRequestException(`User ${user._id} does not exist`);
    }
    return profile;
  }

  async updateProfileUser(
    userId: string,
    body: UpdateUserDto,
  ): Promise<UserResponseDto> {
    if (!userId) throw new BadRequestException('userId is required');

    const user = await this.usersService.updateUserProfile(
      userId,
      this.toUserUpdate(body),
    );
    if (!user) throw new BadRequestException('User does not exist');
    return user;
  }

  async changePassword(
    input: ChangeOwnPasswordInput,
  ): Promise<{ message: string }> {
    try {
      const { confirmPassword, newPassword, oldPassword, userId } = input;
      const checkInput: CheckPasswordInput = {
        userId,
        password: oldPassword,
      };
      if (!(await this.usersService.checkPassword(checkInput))) {
        throw new BadRequestException('Old password is incorrect');
      }
      if (newPassword !== confirmPassword) {
        throw new BadRequestException('Passwords do not match');
      }

      const changeInput: ChangePasswordInput = { userId, newPassword };
      if (!(await this.usersService.changeUserPassword(changeInput))) {
        throw new InternalServerErrorException('Password change failed');
      }

      await this.usersService.revokeAllRefreshTokens(userId);
      return { message: 'Password change successfully' };
    } catch (error: unknown) {
      if (error instanceof HttpException) throw error;
      this.logger.error(
        `Password change failed for user ${input?.userId}`,
        getErrorStack(error),
      );
      throw new InternalServerErrorException('Failed to change password');
    }
  }

  async logout(userId: string): Promise<{ message: string }> {
    if (!(await this.usersService.removeRefreshToken(userId))) {
      throw new InternalServerErrorException('Failed to remove refresh token');
    }
    return { message: 'Logout successfully' };
  }

  private toUserUpdate(body: UpdateUserDto): UserUpdateInput {
    return Object.fromEntries(
      Object.entries({
        avatarUrl: body.avatarUrl,
        bio: body.bio,
        birthDate: body.birthDate,
        gender: body.gender,
        name: body.name,
        phone: body.phone,
      }).filter(([, value]) => value !== undefined),
    ) as UserUpdateInput;
  }

  private toClientUser(user: UserResponseDto): UserResponseDto {
    return {
      _id: user._id,
      email: user.email,
      username: user.username,
      name: user.name,
      avatarUrl: user.avatarUrl,
      bio: user.bio,
      isActive: user.isActive,
      birthDate: user.birthDate,
      gender: user.gender,
      role: user.role,
    };
  }
}
