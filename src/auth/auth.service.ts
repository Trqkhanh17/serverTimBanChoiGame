import {
  BadRequestException,
  ConflictException,
  Injectable,
} from '@nestjs/common';
import { UsersService } from 'src/modules/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { comparePasswordHelper } from '@/common/helpers/ulti';
import { CreateUserDto } from '@/modules/users/dto/create-user.dto';
import { AuthResponseDto, UserResponseDto } from '@/auth/dto/auth.respone';
import { ConfigService } from '@nestjs/config';
import type {
  TokenPayload,
  TokenUser,
  UserWithoutPassword,
} from '@/common/types/auth.types';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async validateUser(
    userName: string,
    pass: string,
  ): Promise<UserWithoutPassword | null> {
    const user = await this.usersService.findUserByEmail(userName);
    if (!user) return null;
    const isValidPassword = await comparePasswordHelper(pass, user.password);
    if (!isValidPassword) return null;
    const { password, ...result } = user.toObject ? user.toObject() : user;
    return result;
  }

  async createToken(user: TokenUser) {
    const payLoadAccessToken = { sub: user._id, username: user.email };
    const payLoadRefreshToken = { sub: user._id, type: 'refresh' };
    const access_token = await this.jwtService.signAsync(payLoadAccessToken);
    const refresh_token = await this.jwtService.signAsync(payLoadRefreshToken, {
      secret: this.configService.get<string>('REFRESH_JWT_SECRET'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_TOKEN_EXPIRED'),
    });
    return {
      access_token,
      refresh_token,
    };
  }

  async login(user: UserWithoutPassword): Promise<AuthResponseDto> {
    const { access_token, refresh_token } = await this.createToken(user);
    const dataUserForClient: UserResponseDto = {
      _id: user._id,
      email: user.email,
      username: user.username,
      name: user.name,
      avatarUrl: user.avatarUrl,
      bio: user.bio,
      isActive: user.isActive,
    };
    return {
      access_token: access_token,
      refresh_token: refresh_token,
      user: dataUserForClient,
    };
  }

  async register(data: CreateUserDto) {
    if (!data) throw new BadRequestException('dữ liệu không hợp lệ');
    const isEmailExist = await this.usersService.isEmailExist(data.email);
    if (isEmailExist)
      throw new ConflictException(
        'email đã được sử dụng vui lòng chọn email khác',
      );

    const user = await this.usersService.createUser(data);
    const { access_token, refresh_token } = await this.createToken(user);
    const dataUserForClient: UserResponseDto = {
      _id: user._id,
      email: user.email,
      username: user.username,
      name: user.name,
      isActive: user.isActive,
    };
    return {
      access_token,
      refresh_token: refresh_token,
      user: dataUserForClient,
    };
  }

  async getProfileUser(user: TokenPayload): Promise<UserResponseDto> {
    const userProfile = await this.usersService.getProfileUser(user.email);
    if (!userProfile)
      throw new BadRequestException(`User có email ${user.email}`);

    const dataUserForClient: UserResponseDto = {
      _id: userProfile._id,
      email: userProfile.email,
      username: userProfile.username,
      name: userProfile.name,
      avatarUrl: userProfile.avatarUrl,
      bio: userProfile.bio,
      isActive: userProfile.isActive,
      gender: userProfile.gender,
      birthDate: userProfile.birthDate,
    };

    return dataUserForClient;
  }
}
