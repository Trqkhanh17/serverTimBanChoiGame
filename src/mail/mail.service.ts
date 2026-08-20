import { MailerService } from '@nestjs-modules/mailer';
import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  constructor(private readonly mailerService: MailerService) {}
  async sendVerifyEmailUser(
    email: string,
    verifyUrl: string,
    ctx?: { name?: string; expiresIn?: number },
  ) {
    try {
      await this.mailerService.sendMail({
        to: email,
        subject: 'Email Verification – AI Travel Planner',
        template: 'verify-account',
        context: {
          appName: 'AI Travel Planner',
          name: ctx?.name ?? 'You',
          verifyUrl,
          expiresIn: ctx?.expiresIn ?? 15,
          supportEmail: 'support@example.com',
        },
      });
    } catch (error) {
      console.log(error);
    }
  }

  async sendOtpForgotPassword(
    email: string,
    otpCode: string,
    ctx?: { name?: string; expiresIn?: number },
  ) {
    try {
      await this.mailerService.sendMail({
        to: email,
        subject: 'Your OTP Code to reset password – AI Travel Planner',
        template: 'forgot-password',
        context: {
          appName: 'AI Travel Planner',
          name: ctx?.name ?? 'You',
          otpCode,
          expiresIn: ctx?.expiresIn ?? 5,
          supportEmail: 'support@example.com',
        },
      });
      this.logger.log(`OTP sent to ${email}`);
    } catch (error) {
      this.logger.error('sendOtpEmail error', error.stack);
      throw error;
    }
  }
}
