// src/mail/mail.module.ts
import { Module } from '@nestjs/common';
import { MailController } from './mail.controller';
import { MailService } from './mail.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MailerModule } from '@nestjs-modules/mailer';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';
import { join } from 'path';

@Module({
  imports: [
    ConfigModule,
    MailerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => {
        const host = config.get<string>('MAIL_HOST')!;
        const port = Number(config.get('MAIL_PORT') ?? 587);
        const secure = port;
        return {
          transport: {
            host,
            port,
            secure,
            auth: {
              user: config.get<string>('MAIL_USER')!,
              pass: config.get<string>('MAIL_PASS')!,
            },
          },
          defaults: { from: config.get<string>('MAIL_FROM') },
          template: {
            dir: join(__dirname, 'templates'),
            adapter: new HandlebarsAdapter(),
            options: { strict: true },
          },
        };
      },
    }),
  ],
  controllers: [MailController],
  providers: [MailService],
  exports: [MailService],
})
export class MailModule {}
