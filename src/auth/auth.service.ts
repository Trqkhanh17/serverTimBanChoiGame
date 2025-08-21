import {
  BadGatewayException,
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
  Logger,
  InternalServerErrorException,
  HttpException,
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

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
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

  async generateRefreshToken(user: UserResponseDto) {
    const payLoadRefreshToken = { sub: user._id, type: 'refresh' };
    const refresh_token = await this.jwtService.signAsync(payLoadRefreshToken, {
      secret: this.configService.get<string>('REFRESH_JWT_SECRET'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_TOKEN_EXPIRED'),
    });
    return refresh_token;
  }

  async generateAccessToken(user: UserResponseDto, refreshToken: string) {
    try {
      const checkUser = await this.usersService.findUserById(user._id);
      if (!checkUser) throw new BadRequestException();
      const RefreshTokenInDatabase = await this.usersService.getRefreshToken(
        user._id,
      );
      if (!RefreshTokenInDatabase)
        throw new UnauthorizedException('Refresh token invalid');
      if (refreshToken !== RefreshTokenInDatabase)
        throw new UnauthorizedException('Refresh token invalid');
      const payLoadAccessToken = { sub: user._id, email: user.email };
      const access_token = await this.jwtService.signAsync(payLoadAccessToken);
      this.logger.log('Generate access token');
      return access_token;
    } catch (error) {
      this.logger.error(`Generate error access token user:${user._id}`);
      if (error instanceof HttpException) throw error;
      throw new InternalServerErrorException('Faild to generate access token');
    }
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

  async login(user: UserResponseDto): Promise<AuthResponseDto | undefined> {
    try {
      if (!user) throw new BadRequestException();
      const refresh_token = await this.generateRefreshToken(user);
      await this.usersService.addRefreshTokenToDB(refresh_token, user.email);

      const access_token = await this.generateAccessToken(user, refresh_token);

      const dataUserForClient: UserResponseDto = {
        _id: user._id,
        email: user.email,
        username: user.username,
        name: user.name,
        avatarUrl: user.avatarUrl,
        bio: user.bio,
        isActive: user.isActive,
      };
      this.logger.log(`Login successful: ${user.email}`);
      return {
        message: 'Login successful',
        access_token: access_token,
        refresh_token: refresh_token,
        user: dataUserForClient,
      };
    } catch (error) {
      this.logger.error(`Login failed for user ${user?.email}`, error.stack);
      throw new InternalServerErrorException('Faild to Login');
    }
  }

  async register(data: CreateUserDto): Promise<AuthResponseDto> {
    try {
      if (!data) throw new BadRequestException('Invalid request data');

      const isEmailExist = await this.usersService.isEmailExist(data.email);
      if (isEmailExist)
        throw new ConflictException(
          'Email is already in use, please choose another one',
        );

      const user = await this.usersService.createUser(data);
      const refresh_token = await this.generateRefreshToken(user);
      const access_token = await this.generateAccessToken(user, refresh_token);

      const added = await this.usersService.addRefreshTokenToDB(
        refresh_token,
        user.email,
      );
      if (!added) {
        this.logger.error(`Failed to add refresh token for ${user.email}`);
        throw new InternalServerErrorException('Failed to add refresh token');
      }

      const dataForClient: UserResponseDto = {
        _id: user._id,
        email: user.email,
        name: user.name,
        username: user.username,
        isActive: user.isActive,
      };

      this.logger.log(`Account created successfully: ${user.email}`);
      return {
        message: 'Account created successfully',
        access_token,
        refresh_token,
        user: dataForClient,
      };
    } catch (error) {
      this.logger.error(`Register error for ${data?.email}`, error.stack);
      if (error instanceof HttpException) throw error;

      throw new InternalServerErrorException(
        'Failed to create user in database',
      );
    }
  }

  async getProfileUser(user: UserResponseDto) {
    const userProfile = await this.usersService.getProfileUser(user.email);
    if (!userProfile)
      throw new BadRequestException(`User ${user.email} no exist`);
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
    if (!user) throw new BadRequestException(`User no exist`);
    return user;
  }

  async resetPassword(data: ResetPasswordDto): Promise<boolean> {
    if (!data) throw new BadRequestException();
    const result = await this.usersService.resetPassword(data);
    return result ? true : false;
  }

  async logout(_id: string) {
    const result = await this.usersService.removeRefreshToken(_id);
    if (!result) {
      this.logger.warn(`Failed to remove refresh token for user: ${_id}`);
      throw new InternalServerErrorException('Failed to remove refresh token');
    }
    return { message: 'Logout successful' };
  }
}
