import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import type { Request } from 'express';

export class OptionalJwtAccessGuard extends AuthGuard('jwt-access') {
  handleRequest<TUser>(
    err: Error | null,
    user: TUser | false,
    _info: unknown,
    context: ExecutionContext,
  ): TUser | undefined {
    const request = context.switchToHttp().getRequest<Request>();
    if (!request.headers.authorization) return undefined;
    if (err || !user) throw err || new UnauthorizedException();
    return user;
  }
}
