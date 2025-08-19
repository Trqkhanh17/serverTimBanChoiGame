import {
  BadGatewayException,
  BadRequestException,
  ConflictException,
  Injectable,
} from '@nestjs/common';
import { UsersService } from 'src/modules/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { comparePasswordHelper } from '@/common/helpers/ulti';
import { CreateUserDto } from '@/modules/users/dto/create-user.dto';
import { ConfigService } from '@nestjs/config';
import { UpdateUserDto } from '@/modules/users/dto/update-user.dto';
import { ResetPasswordDto } from '@/modules/users/dto/reset-password.user.Dto';
import { UserResponseDto } from '@/modules/users/dto/user-response.dto';
import { AuthResponseDto } from '@/auth/dto/auth-response.dto';
import { UserDocument } from '@/common/types/user.types';

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
  ): Promise<UserResponseDto | null> {
    const user = await this.usersService.findUserByEmail(userName);
    if (!user) return null;
    const isValidPassword = await comparePasswordHelper(pass, user.password);
    if (!isValidPassword) return null;
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
      isBanned: user.isBanned,
    };
    return result;
  }

  async generateRefreshToken(user) {
    const payLoadRefreshToken = { sub: user._id, type: 'refresh' };
    const refresh_token = await this.jwtService.signAsync(payLoadRefreshToken, {
      secret: this.configService.get<string>('REFRESH_JWT_SECRET'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_TOKEN_EXPIRED'),
    });
    return refresh_token;
  }
  async generateAccessToken(user) {
    const payLoadAccessToken = { sub: user._id, email: user.email };
    const access_token = await this.jwtService.signAsync(payLoadAccessToken);
    return access_token;
  }

  async generateRessetPasswordToken(email: string): Promise<string> {
    const user = await this.usersService.findUserByEmail(email);
    if (!user) throw new BadRequestException();
    const payLoadResetPasswordToken = {
      sub: user._id,
      email: user.email,
      type: 'reset',
    };
    const reset_paswordtoken = await this.jwtService.signAsync(
      payLoadResetPasswordToken,
      {
        secret: this.configService.get<string>('RESETPASSWORD_JWT_SECRET'),
        expiresIn: this.configService.get<string>(
          'JWT_RESETPASSWORD_TOKEN_EXPIRED',
        ),
      },
    );
    return reset_paswordtoken;
  }

  async login(user) {
    const access_token = await this.generateAccessToken(user);
    const refresh_token = await this.generateRefreshToken(user);
    console.log('date: ', new Date());

    await this.usersService.addRefreshTokenToDB(refresh_token, user.email);
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

  async register(data: CreateUserDto): Promise<AuthResponseDto> {
    if (!data) throw new BadRequestException('dữ liệu không hợp lệ');
    const isEmailExist = await this.usersService.isEmailExist(data.email);
    if (isEmailExist)
      throw new ConflictException(
        'email đã được sử dụng vui lòng chọn email khác',
      );

    const user = await this.usersService.createUser(data);
    const access_token = await this.generateAccessToken(user);
    const refresh_token = await this.generateRefreshToken(user);
    const addRefreshTokenToDB = await this.usersService.addRefreshTokenToDB(
      refresh_token,
      user.email,
    );
    if (!addRefreshTokenToDB)
      throw new BadGatewayException('đã có lỗi xảy ra khi thêm token');
    const dataForClient: UserResponseDto = {
      _id: user._id,
      email: user.email,
      name: user.name,
      username: user.username,
      isActive: user.isActive,
    };
    return {
      access_token,
      refresh_token: refresh_token,
      user: dataForClient,
    };
  }

  async getProfileUser(user: UserResponseDto) {
    const userProfile = await this.usersService.getProfileUser(user.email);
    if (!userProfile)
      throw new BadRequestException(`User có email ${user.email}`);
    return userProfile;
  }

  async getUserByid(sub: string) {
    const user = await this.usersService.findUserById(sub);
    if (!user) throw new BadGatewayException();
    const { password, ...result } = user.toObject ? user.toObject() : user;
    return result;
  }

  async updateProfileUser(email: string, body: UpdateUserDto) {
    if (!email) throw new BadRequestException();
    const user = await this.usersService.updateUserProfile(email, body);
    if (!user) throw new BadRequestException(`User không tồn tại`);
    return user;
  }

  async resetPassword(data: ResetPasswordDto): Promise<boolean> {
    if (!data) throw new BadRequestException();
    const result = await this.usersService.resetPassword(data);
    return result ? true : false;
  }
}
