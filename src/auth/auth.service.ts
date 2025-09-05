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
import {
  comparePasswordHelper,
  hashPasswordHelper,
} from '@/common/helpers/ulti';
import { ConfigService } from '@nestjs/config';
import { UpdateUserDto } from '@/auth/dto/update-user.dto';
import { ResetPasswordDto } from '@/modules/users/dto/reset-password.user.Dto';
import { UserResponseDto } from '@/modules/users/dto/user-response.dto';
import { AuthResponseDto } from '@/auth/dto/auth-response.dto';
import { RegisterDto } from '@/auth/dto/register.Dto';
import { AuthUser } from '@/common/types/auth.types';
import {
  UserCreateInput,
  UserDocument,
  UserUpdateInput,
} from '@/common/types/user.types';
import { v4 as uuidv4 } from 'uuid';
import { MailService } from '@/mail/mail.service';
import { CreateOtpInput } from '@/common/types/opt.types';
import { OtpService } from '@/modules/otp/otp.service';
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly mailService: MailService,
    private readonly otpService: OtpService,
  ) {}

  async validateUser(userName: string, pass: string): Promise<AuthUser | null> {
    const user = await this.usersService.findByEmailForAuth(userName);
    if (!user) return null;
    const isValidPassword = await comparePasswordHelper(pass, user.password);
    if (!isValidPassword) return null;
    const result = {
      _id: user._id.toString(),
      email: user.email,
      username: user.username,
      name: user.name,
      isActive: user.isActive,
      isBanned: user.isBanned,
    };

    return result;
  }

  async generateRefreshToken(user: UserResponseDto): Promise<string> {
    const payLoadRefreshToken = { sub: user._id, type: 'refresh' };
    const refresh_token = await this.jwtService.signAsync(payLoadRefreshToken, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRED'),
    });
    return refresh_token;
  }

  async generateVerifyEmail(
    user: UserResponseDto,
    jti: string,
  ): Promise<string> {
    const payLoadRefreshToken = { sub: user._id, type: 'email_verify', jti };
    const verifyEmail_token = await this.jwtService.signAsync(
      payLoadRefreshToken,
      {
        secret: this.configService.get<string>('JWT_EMAIL_VERIFY_SECRET'),
        expiresIn:
          this.configService.get<string>('EMAIL_VERIFY_EXPIRE') ?? '15m',
      },
    );
    return verifyEmail_token;
  }

  async generateAccessToken(
    user: UserResponseDto,
    refreshToken: string,
  ): Promise<string> {
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
      const payLoadAccessToken = {
        sub: user._id,
        email: user.email,
        type: 'accessToken',
      };
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
    const user = await this.usersService.findByEmailForAuth(email);
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

  async login(
    user: UserResponseDto,
  ): Promise<AuthResponseDto | undefined | null> {
    try {
      if (!user) throw new BadRequestException();
      const refresh_token = await this.generateRefreshToken(user);
      await this.usersService.addRefreshTokenToDB(refresh_token, user._id);

      const access_token = await this.generateAccessToken(user, refresh_token);

      const dataUserForClient: UserResponseDto = {
        _id: user._id,
        email: user.email,
        username: user.username,
        name: user.name,
        avatarUrl: user.avatarUrl,
        bio: user.bio,
        isActive: user.isActive,
        birthDate: user.birthDate,
        gender: user.gender,
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

  async register(data: RegisterDto): Promise<AuthResponseDto> {
    try {
      if (!data) throw new BadRequestException('Invalid request data');

      const isEmailExist = await this.usersService.isEmailExist(data.email);
      if (isEmailExist)
        throw new ConflictException(
          `Email ${data.email} is already in use, please choose another one`,
        );
      const isUserNameExist = await this.usersService.isUserNameExist(
        data.username,
      );
      if (isUserNameExist)
        throw new ConflictException(
          `Email ${data.username} is already in use, please choose another one`,
        );
      const passwordHash = await hashPasswordHelper(data.password);
      const dataCreateInput: UserCreateInput = {
        email: data.email,
        passwordHash: passwordHash,
        username: data.username,
        name: data.name,
      };
      const user = await this.usersService.createUser(dataCreateInput);
      const refresh_token = await this.generateRefreshToken(user);
      const added = await this.usersService.addRefreshTokenToDB(
        refresh_token,
        user._id,
      );
      const access_token = await this.generateAccessToken(user, refresh_token);

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
      await this.sendMailUserVerification(dataForClient);
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

  async getProfileUser(user: UserResponseDto): Promise<UserResponseDto> {
    const userProfile = await this.usersService.getProfileUser(user.email);
    if (!userProfile)
      throw new BadRequestException(`User ${user.email} no exist`);
    return userProfile;
  }

  convertDataUpdateUser(body: UpdateUserDto): UserUpdateInput {
    const dataUpdateUser: UserUpdateInput = {
      avatarUrl: body.avatarUrl,
      bio: body.bio,
      birthDate: body.birthDate,
      gender: body.gender,
      name: body.name,
      phone: body.phone,
    };
    return dataUpdateUser;
  }

  async updateProfileUser(
    userId: string,
    body: UpdateUserDto,
  ): Promise<UserResponseDto> {
    if (!userId) throw new BadRequestException('userId is not empty');
    const dataUpdateUser = this.convertDataUpdateUser(body);
    const user = await this.usersService.updateUserProfile(
      userId,
      dataUpdateUser,
    );
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
    return { message: 'Logout successfully' };
  }

  async sendMailUserVerification(user: UserResponseDto) {
    try {
      const jti = uuidv4();
      const setVerifyJti = await this.usersService.setVerifyJti(user._id, jti);
      if (!setVerifyJti)
        throw new BadRequestException('Faild to set VerifyJti');
      const token = await this.generateVerifyEmail(user, jti);
      const verifyUrl = `${this.configService.get<string>('BACKEND_BASE_URL')}auth/verify-email?token=${encodeURIComponent(token)}`;
      await this.mailService.sendVerifyEmailUser(user.email, verifyUrl, {
        name: user.name ?? user.email,
        expiresIn: 15,
      });
      this.logger.log(`Send mail to ${user.email} successfully`);
    } catch (error) {
      this.logger.error(`Faild to send mail ${user.email}`);
    }
  }

  async verifyEmailToken(token: string) {
    let payload: any;
    try {
      payload = await this.jwtService.verifyAsync(token, {
        secret: this.configService.get<string>('JWT_EMAIL_VERIFY_SECRET'),
      });
    } catch {
      throw new BadRequestException('Invalid or expired token');
    }

    if (payload?.type !== 'email_verify' || !payload?.sub || !payload?.jti) {
      throw new BadRequestException('Invalid token payload');
    }

    const ok = await this.usersService.consumeVerifyJti(
      payload.sub,
      payload.jti,
    );
    if (!ok) throw new BadRequestException('Token already used or invalid');
    this.logger.log(`verify user ${payload}`);
    return { message: 'Email verified successfully' };
  }

  async sendUserForgotPassword(email: string) {
    const user = await this.usersService.findUserByEmail(email);
    if (!user) throw new BadRequestException('User not found with this email');
    try {
      const otpInput: CreateOtpInput = {
        userId: user._id,
        expiresInMinutes: 5,
        purpose: 'reset_password',
      };
      const otp = await this.otpService.createOtp(otpInput);
      if (!otp) throw new BadRequestException();
      await this.mailService.sendOtpForgotPassword(email, otp.otpCode, {
        name: user.name ?? user.email,
        expiresIn: 5,
      });
    } catch (error) {}
  }
}
