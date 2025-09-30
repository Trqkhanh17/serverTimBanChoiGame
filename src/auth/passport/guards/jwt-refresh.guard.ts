import { UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
export class JwtRefreshGuard extends AuthGuard('jwt-refresh') {
  handleRequest(err, user, info, context) {
    const req = context.switchToHttp().getRequest();

    const authHeader = req.headers['authorization'];
    const refreshToken = authHeader?.replace('Bearer ', '');

    if (err || !user) {
      throw err || new UnauthorizedException();
    }

    req.refreshToken = refreshToken;

    return user; // user = payload decode từ JWT
  }
}
6;
