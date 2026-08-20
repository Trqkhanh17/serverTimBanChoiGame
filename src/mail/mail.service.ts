import { Injectable, Logger } from '@nestjs/common';
import { getErrorStack } from '@/common/helpers/error.helpers';
import { ConfigService } from '@nestjs/config';
import { createTransport, type Transporter } from 'nodemailer';
import { randomUUID } from 'crypto';

interface MailMessage {
  to: string;
  subject: string;
  html: string;
}

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private readonly transporter: Transporter | null;

  constructor(private readonly configService: ConfigService) {
    const host = configService.get<string>('MAIL_HOST');
    const port = Number(configService.get<string>('MAIL_PORT') ?? 587);
    const timeoutMs = Number(
      configService.get<string>('EXTERNAL_REQUEST_TIMEOUT_MS') ?? 25_000,
    );
    this.transporter = host
      ? createTransport({
          host,
          port,
          secure: port === 465,
          auth: {
            user: configService.get<string>('MAIL_USER'),
            pass: configService.get<string>('MAIL_PASS'),
          },
          connectionTimeout: timeoutMs,
          greetingTimeout: timeoutMs,
          socketTimeout: timeoutMs,
        })
      : null;
  }

  private escapeHtml(value: string): string {
    return value.replace(
      /[&<>'"]/g,
      (character) =>
        ({
          '&': '&amp;',
          '<': '&lt;',
          '>': '&gt;',
          "'": '&#39;',
          '"': '&quot;',
        })[character] ?? character,
    );
  }

  private async send(message: MailMessage): Promise<void> {
    const from = this.configService.get<string>('MAIL_FROM');
    if (!from) throw new Error('MAIL_FROM is not configured');

    const resendApiKey = this.configService.get<string>('RESEND_API_KEY');
    if (resendApiKey) {
      await this.sendWithResend(resendApiKey, from, message);
      return;
    }

    if (!this.transporter) {
      throw new Error('Email provider is not configured');
    }
    await this.transporter.sendMail({ from, ...message });
  }

  private async sendWithResend(
    apiKey: string,
    from: string,
    message: MailMessage,
  ): Promise<void> {
    const timeoutMs = Number(
      this.configService.get<string>('EXTERNAL_REQUEST_TIMEOUT_MS') ?? 25_000,
    );
    const idempotencyKey = randomUUID();
    let lastStatus: number | undefined;
    for (let attempt = 1; attempt <= 2; attempt += 1) {
      const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': idempotencyKey,
        },
        body: JSON.stringify({ from, ...message }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (response.ok) return;
      lastStatus = response.status;
      if (response.status < 500 && response.status !== 429) break;
    }
    throw new Error(`Resend API returned HTTP ${lastStatus ?? 'unknown'}`);
  }

  async sendVerifyEmailUser(
    email: string,
    verifyUrl: string,
    ctx?: { name?: string; expiresIn?: number },
  ): Promise<void> {
    try {
      const name = this.escapeHtml(ctx?.name ?? 'Bạn');
      const safeUrl = this.escapeHtml(verifyUrl);
      await this.send({
        to: email,
        subject: 'Email Verification – AI Travel Planner',
        html: `<h2>Xác minh tài khoản AI Travel Planner</h2>
          <p>Xin chào ${name},</p>
          <p>Nhấn vào liên kết dưới đây để xác minh email. Liên kết hết hạn sau ${ctx?.expiresIn ?? 15} phút.</p>
          <p><a href="${safeUrl}">Xác minh email</a></p>
          <p>Nếu bạn không tạo tài khoản này, hãy bỏ qua email.</p>`,
      });
    } catch (error: unknown) {
      this.logger.error('sendVerifyEmail error', getErrorStack(error));
      throw error;
    }
  }

  async sendOtpForgotPassword(
    email: string,
    otpCode: string,
    ctx?: { name?: string; expiresIn?: number },
  ): Promise<void> {
    try {
      const name = this.escapeHtml(ctx?.name ?? 'Bạn');
      const safeOtp = this.escapeHtml(otpCode);
      await this.send({
        to: email,
        subject: 'Your OTP Code to reset password – AI Travel Planner',
        html: `<h2>Đặt lại mật khẩu AI Travel Planner</h2>
          <p>Xin chào ${name},</p>
          <p>Mã OTP của bạn là:</p>
          <p style="font-size: 28px; font-weight: bold; letter-spacing: 6px">${safeOtp}</p>
          <p>Mã hết hạn sau ${ctx?.expiresIn ?? 5} phút và chỉ sử dụng được một lần.</p>`,
      });
      this.logger.log(`OTP sent to ${email}`);
    } catch (error: unknown) {
      this.logger.error('sendOtpEmail error', getErrorStack(error));
      throw error;
    }
  }
}
