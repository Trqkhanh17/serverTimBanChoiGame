import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { UsersModule } from './modules/users/users.module';
import { AuthModule } from './auth/auth.module';
import { GameProfileModule } from './modules/game-profile/game-profile.module';
import { FriendModule } from './modules/friend/friend.module';
import { MatchSearchModule } from './modules/match-search/match-search.module';
import { OtpModule } from './modules/otp/otp.module';
import { minutes, ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => [
        {
          name: 'default',
          ttl: minutes(
            Number(configService.get<string>('RATE_LIMIT_DEFAULT_TTL')),
          ),
          limit: Number(configService.get<string>('RATE_LIMIT_DEFAULT_TTL')),
        },
      ],
    }),

    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        uri: configService.get<string>('MONGODB_URI'),
      }),
    }),
    UsersModule,
    AuthModule,
    GameProfileModule,
    FriendModule,
    MatchSearchModule,
    OtpModule,
  ],
  controllers: [AppController],
  providers: [AppService, { provide: APP_GUARD, useClass: ThrottlerGuard }],
})
export class AppModule {}
