import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '@/modules/users/users.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt-access') {
  constructor(
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {
    const jwtSecret = configService.get<string>('JWT_ACCESS_SECRET');
    if (!jwtSecret) throw new Error('JWT_ACCESS_SECRET is not configured');

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtSecret,
    });
  }

  async validate(payload: {
    sub: string;
    email: string;
    type: string;
    role: string;
    tokenVersion: number;
  }) {
    if (payload.type !== 'accessToken') {
      throw new UnauthorizedException('Invalid access token');
    }
    const user = await this.usersService.findUserById(payload.sub);
    if (!user || !user.isActive || user.isBanned) {
      throw new UnauthorizedException('Account is inactive or unavailable');
    }
    if (user.refreshTokenVersion !== payload.tokenVersion) {
      throw new UnauthorizedException('Access token has been revoked');
    }
    return {
      _id: payload.sub,
      email: user.email,
      type: payload.type,
      role: user.role,
    };
  }
}
