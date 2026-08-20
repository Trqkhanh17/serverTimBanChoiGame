import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { Logger } from '@nestjs/common';
import { API_PREFIX } from './common/constants/api.constants';
import { configureApplication } from './config/application.setup';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import type { NestExpressApplication } from '@nestjs/platform-express';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  const configService = app.get(ConfigService);
  const port = Number(configService.get<string>('PORT') ?? 8080);
  configureApplication(app);

  const swaggerConfig = new DocumentBuilder()
    .setTitle('AI Travel Planner API')
    .setDescription('Authentication, profile and AI trip planning APIs')
    .setVersion('1.0')
    .addBearerAuth()
    .addApiKey({ type: 'apiKey', in: 'header', name: 'X-Guest-Token' }, 'guest')
    .build();
  const openApiDocument = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup(`${API_PREFIX}/docs`, app, openApiDocument, {
    jsonDocumentUrl: `${API_PREFIX}/docs/openapi.json`,
  });

  const logger = new Logger('HTTP');
  await app.listen(port);
  logger.log(`Server is running on port ${port}`);
  logger.log(`OpenAPI documentation: /${API_PREFIX}/docs`);
}
void bootstrap();
