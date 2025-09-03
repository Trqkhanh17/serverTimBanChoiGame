import { MailerService } from '@nestjs-modules/mailer';
import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class MailService {
  constructor(private readonly mailerService: MailerService) {}
  async sendVerifyEmailUser(
    email: string,
    verifyUrl: string,
    ctx?: { username?: string; expiresIn?: number },
  ) {
    try {
      await this.mailerService.sendMail({
        to: email,
        subject: 'Xác thực email – Tìm bạn chơi Liên Quân',
        template: 'verify-account', // trỏ tới file .hbs ở trên
        context: {
          appName: 'Tìm Bạn Chơi Game',
          username: ctx?.username ?? 'Bạn',
          verifyUrl,
          expiresIn: ctx?.expiresIn ?? 15,
          supportEmail: 'support@example.com',
        },
      });
    } catch (error) {
      console.log(error);
    }
  }

  async sendPasswordReset(email: string, token: string) {
    const url = `http://localhost:3000/auth/reset-password?token=${token}`;

    await this.mailerService.sendMail({
      to: email,
      subject: 'Reset your password',
      template: './reset-password',
      context: { email, url },
    });
  }
}
