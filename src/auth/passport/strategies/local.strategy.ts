import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from '@/auth/auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ usernameField: 'email' });
  }

  async validate(email: string, password: string) {
    const user = await this.authService.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException('Sai tài khoản hoặc mật khẩu');
    }
    if (!user.isActive)
      throw new BadRequestException('Tài khoản chưa được kích hoạt');
    if (user.isBanned)
      throw new BadRequestException(
        'Tài khoản của bạn hiện đã bị khóa vui lòng liên hệ để biết thêm chi tiết',
      );
    return user;
  }
}
