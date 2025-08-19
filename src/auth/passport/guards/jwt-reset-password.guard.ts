import { AuthGuard } from '@nestjs/passport';
export class JwtResetPasswordGuard extends AuthGuard('jwt-reset-password') {}
