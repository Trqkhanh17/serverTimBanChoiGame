import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from 'src/modules/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { comparePasswordHelper } from '@/helpers/ulti';
import { CreateUserDto } from '@/modules/users/dto/create-user.dto';
import { AuthResponseDto } from '@/auth/dto/auth.respone';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async validateUser(userName: string, pass: string): Promise<any> {
    const user = await this.usersService.findUserByEmail(userName);
    if (!user) throw new UnauthorizedException('Sai email hoặc mật khẩu');
    const isValidPassword = await comparePasswordHelper(pass, user.password);
    if (!isValidPassword)
      throw new UnauthorizedException('Sai email hoặc mật khẩu');
    const { password, ...result } = user.toObject ? user.toObject() : user;
    return result;
  }

  async login(email: string, pass: string): Promise<AuthResponseDto> {
    const user = await this.usersService.findUserByEmail(email);
    if (!user) throw new UnauthorizedException('Sai email hoặc mật khẩu');
    const isValidPassword = await comparePasswordHelper(pass, user.password);
    if (!isValidPassword)
      throw new UnauthorizedException('Sai email hoặc mật khẩu');
    const payLoadAccessToken = { sub: user._id, username: user.email };
    const payLoadRefreshToken = { sub: user._id, type: 'refresh' };
    const access_token = await this.jwtService.signAsync(payLoadAccessToken);
    const refresh_token = await this.jwtService.signAsync(payLoadRefreshToken, {
      secret: this.configService.get<string>('REFRESH_JWT_SECRET'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_TOKEN_EXPIRED'),
    });
    const dataUserForClient = {
      _id: user._id,
      email: user.email,
      username: user.username,
      name: user.name,
      avatarUrl: user.avatarUrl,
      bio: user.bio,
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
    const payLoadAccessToken = { sub: user._id, username: user.email };
    const payLoadRefreshToken = { sub: user._id, type: 'refresh' };
    const access_token = await this.jwtService.signAsync(payLoadAccessToken);
    const refresh_token = await this.jwtService.signAsync(payLoadRefreshToken, {
      secret: this.configService.get<string>('REFRESH_JWT_SECRET'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_TOKEN_EXPIRED'),
    });
    const dataUserForClient = {
      _id: user._id,
      email: user.email,
      username: user.username,
      name: user.name,
    };
    return {
      access_token,
      refresh_token: refresh_token,
      user: dataUserForClient,
    };
  }
}
