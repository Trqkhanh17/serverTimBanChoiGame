import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const port = configService.get('PORT');
  // Enable CORS for requests from frontend
  // Prefer an explicit FRONTEND_URL env variable; fall back to BACKEND_BASE_URL or allow all
  const frontendOrigin =
    configService.get<string>('FRONTEND_URL') ||
    configService.get<string>('BACKEND_BASE_URL') ||
    '*';
  app.enableCors({
    origin: frontendOrigin === '*' ? true : frontendOrigin,
    credentials: true,
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'Accept',
      'Origin',
      'X-Requested-With',
    ],
  });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  app.setGlobalPrefix('api/v1');
  await app.listen(port);
}
bootstrap();
