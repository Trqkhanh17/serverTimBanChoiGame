import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from '@/auth/auth.service';
import { AuthUser } from '@/common/types/auth.types';
import { isEmail } from 'class-validator';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ usernameField: 'email' });
  }

  async validate(email: string, password: string): Promise<AuthUser> {
    if (!email || !password) {
      throw new BadRequestException('Email and password are required');
    }
    if (!isEmail(email)) throw new BadRequestException('Invalid email format');
    const user = await this.authService.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException('Incorrect email or password');
    }
    if (!user.isActive)
      throw new BadRequestException('Your account has not been activated');
    if (user.isBanned)
      throw new BadRequestException(
        'Your account has been locked. Please contact support for more details',
      );
    return user as AuthUser;
  }
}
