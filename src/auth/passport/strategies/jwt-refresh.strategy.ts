import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '@/modules/users/users.service';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {
    const jwtSecret = configService.get<string>('JWT_REFRESH_SECRET');
    if (!jwtSecret) throw new Error('JWT_REFRESH_SECRET is not configured');
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: jwtSecret,
      ignoreExpiration: false,
    });
  }

  async validate(payload: {
    sub: string;
    email: string;
    type: string;
    role: string;
    tokenVersion: number;
  }) {
    if (payload.type !== 'refresh') {
      throw new UnauthorizedException('Invalid refresh token');
    }
    const user = await this.usersService.findUserById(payload.sub);
    if (!user || !user.isActive || user.isBanned) {
      throw new UnauthorizedException('Account is inactive or unavailable');
    }
    if (user.refreshTokenVersion !== payload.tokenVersion) {
      throw new UnauthorizedException('Refresh token has been revoked');
    }
    return {
      _id: payload.sub,
      email: user.email,
      type: payload.type,
      tokenVersion: payload.tokenVersion,
      role: user.role,
    };
  }
}
