import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';

@Injectable()
export class MailService {
  constructor(private readonly mailerService: MailerService) {}
  async sendUserConfirmation(email: string, token: string) {
    const url = `http://localhost:3000/auth/confirm?token=${token}`;

    await this.mailerService.sendMail({
      to: email,
      subject: 'Confirm your Email',
      template: './confirmation',
      context: { email, url },
    });
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
