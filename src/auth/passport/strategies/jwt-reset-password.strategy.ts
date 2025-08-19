import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtResetPasswordStrategy extends PassportStrategy(
  Strategy,
  'jwt-reset-password',
) {
  constructor(private configService: ConfigService) {
    const jwtSecret = configService.get<string>('RESETPASSWORD_JWT_SECRET');
    if (!jwtSecret) throw new Error('RESETPASSWORD_JWT_SECRET is not defind');
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), // hoặc lấy từ cookie
      secretOrKey: jwtSecret,
      ignoreExpiration: false,
    });
  }

  async validate(payload: { sub: string; email: string; type: string }) {
    return { _id: payload.sub, email: payload.email, type: payload.type };
  }
}
