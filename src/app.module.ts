import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { UsersModule } from './modules/users/users.module';
import { AuthModule } from './auth/auth.module';
import { OtpModule } from './modules/otp/otp.module';
import { TripPlannerModule } from './modules/trip-planner/trip-planner.module';
import { minutes, ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { validateEnvironment } from './config/environment.validation';
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validate: validateEnvironment,
    }),
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => [
        {
          name: 'default',
          ttl: minutes(
            Number(configService.get<string>('RATE_LIMIT_DEFAULT_TTL') ?? 1),
          ),
          limit: Number(
            configService.get<string>('RATE_LIMIT_DEFAULT_LIMIT') ?? 60,
          ),
        },
      ],
    }),

    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const uri = configService.get<string>('MONGODB_URI');
        if (!uri) throw new Error('MONGODB_URI is required');
        return { uri };
      },
    }),
    UsersModule,
    AuthModule,
    OtpModule,
    TripPlannerModule,
  ],
  controllers: [AppController],
  providers: [AppService, { provide: APP_GUARD, useClass: ThrottlerGuard }],
})
export class AppModule {}
