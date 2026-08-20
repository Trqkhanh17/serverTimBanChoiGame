import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectConnection } from '@nestjs/mongoose';
import { ConnectionStates, type Connection } from 'mongoose';

@Injectable()
export class AppService {
  constructor(
    @InjectConnection() private readonly connection: Connection,
    private readonly configService: ConfigService,
  ) {}

  getHealth() {
    const databaseReady =
      this.connection.readyState === ConnectionStates.connected;
    return {
      status: databaseReady ? 'ok' : 'degraded',
      database: databaseReady ? 'connected' : 'disconnected',
      ai: this.configService.get<string>('GEMINI_API_KEY')
        ? 'configured'
        : 'not_configured',
      timestamp: new Date().toISOString(),
    };
  }
}
