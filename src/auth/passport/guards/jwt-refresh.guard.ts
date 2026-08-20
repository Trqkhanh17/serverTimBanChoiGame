import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import type { Request } from 'express';

interface RefreshTokenRequest extends Request {
  refreshToken?: string;
}

export class JwtRefreshGuard extends AuthGuard('jwt-refresh') {
  handleRequest<TUser>(
    err: Error | null,
    user: TUser | false,
    _info: unknown,
    context: ExecutionContext,
  ): TUser {
    const req = context.switchToHttp().getRequest<RefreshTokenRequest>();

    const authHeader = req.headers.authorization;
    const refreshToken = authHeader?.match(/^Bearer\s+(.+)$/i)?.[1];

    if (err || !user) {
      throw err || new UnauthorizedException();
    }

    if (!refreshToken) throw new UnauthorizedException();
    req.refreshToken = refreshToken;

    return user; // user = payload decode từ JWT
  }
}
