import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { v4 as uuidv4 } from 'uuid';
import { API_PREFIX } from '@/common/constants/api.constants';
import { MailService } from '@/mail/mail.service';
import { UserResponseDto } from '@/modules/users/dto/user-response.dto';
import { UsersService } from '@/modules/users/users.service';
import { AuthTokenService } from './auth-token.service';

@Injectable()
export class EmailVerificationService {
  private readonly logger = new Logger(EmailVerificationService.name);

  constructor(
    private readonly usersService: UsersService,
    private readonly tokenService: AuthTokenService,
    private readonly mailService: MailService,
    private readonly configService: ConfigService,
  ) {}

  async send(user: UserResponseDto): Promise<void> {
    try {
      const jti = uuidv4();
      if (!(await this.usersService.setVerifyJti(user._id, jti))) {
        throw new BadRequestException('Failed to set verification token');
      }

      const token = await this.tokenService.generateEmailVerificationToken(
        user._id,
        jti,
      );
      const baseUrl = this.configService.get<string>('BACKEND_BASE_URL');
      if (!baseUrl) throw new Error('BACKEND_BASE_URL is not configured');
      const verifyUrl = `${baseUrl}/${API_PREFIX}/auth/verify-email?token=${encodeURIComponent(token)}`;

      await this.mailService.sendVerifyEmailUser(user.email, verifyUrl, {
        name: user.name ?? user.email,
        expiresIn: this.getExpirationMinutes(),
      });
      this.logger.log(`Verification email sent to ${user.email}`);
    } catch (error: unknown) {
      this.logger.error(
        `Failed to send verification email to ${user.email}`,
        error instanceof Error ? error.stack : undefined,
      );
    }
  }

  async verify(token: string): Promise<{ message: string }> {
    const payload = await this.tokenService.verifyEmailVerificationToken(token);
    if (payload.type !== 'email_verify' || !payload.sub || !payload.jti) {
      throw new BadRequestException('Invalid token payload');
    }

    const consumed = await this.usersService.consumeVerifyJti(
      payload.sub,
      payload.jti,
    );
    if (!consumed) {
      throw new BadRequestException('Token already used or invalid');
    }
    return { message: 'Email verified successfully' };
  }

  async resend(email: string): Promise<void> {
    const user = await this.usersService.findUserByEmail(email);
    if (!user || user.isActive) return;
    await this.send({
      _id: user._id.toString(),
      email: user.email,
      username: user.username,
      name: user.name,
      isActive: user.isActive,
    });
  }

  private getExpirationMinutes(): number {
    return parseInt(
      this.configService.get<string>('JWT_EMAIL_VERIFY_EXPIRE') ?? '15',
      10,
    );
  }
}
