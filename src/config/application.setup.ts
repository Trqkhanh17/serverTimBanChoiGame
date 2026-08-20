import { randomUUID } from 'crypto';
import { Logger, ValidationPipe, type INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { NestExpressApplication } from '@nestjs/platform-express';
import compression from 'compression';
import type { NextFunction, Request, Response } from 'express';
import helmet from 'helmet';
import { API_PREFIX } from '@/common/constants/api.constants';

interface RequestWithId extends Request {
  requestId?: string;
}

export function configureApplication(app: INestApplication): void {
  const configService = app.get(ConfigService);
  const expressApp = app as NestExpressApplication;
  const isProduction = configService.get<string>('NODE_ENV') === 'production';
  const trustProxy = configService.get<string>('TRUST_PROXY') ?? '1';

  expressApp.set('trust proxy', parseTrustProxy(trustProxy));
  app.enableShutdownHooks();
  app.use(helmet());
  app.use(compression());
  app.enableCors({
    origin: buildCorsOrigin(configService, isProduction),
    credentials: false,
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'Accept',
      'Origin',
      'X-Requested-With',
      'X-Guest-Token',
      'X-Request-Id',
    ],
    exposedHeaders: ['X-Request-Id'],
  });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      validationError: { target: false, value: false },
    }),
  );
  app.use(createSafeRequestLogger());
  app.setGlobalPrefix(API_PREFIX);
}

function buildCorsOrigin(
  configService: ConfigService,
  isProduction: boolean,
): string[] | boolean {
  const configuredOrigins = (configService.get<string>('FRONTEND_URL') ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

  if (configuredOrigins.length > 0) return configuredOrigins;
  if (isProduction) throw new Error('FRONTEND_URL is required in production');
  return true;
}

function createSafeRequestLogger() {
  const logger = new Logger('HTTP');
  return (request: RequestWithId, response: Response, next: NextFunction) => {
    const startedAt = process.hrtime.bigint();
    const suppliedRequestId = request.header('x-request-id');
    const requestId =
      suppliedRequestId && /^[a-zA-Z0-9._-]{1,100}$/.test(suppliedRequestId)
        ? suppliedRequestId
        : randomUUID();
    request.requestId = requestId;
    response.setHeader('X-Request-Id', requestId);

    response.on('finish', () => {
      const durationMs =
        Number(process.hrtime.bigint() - startedAt) / 1_000_000;
      // request.path intentionally excludes query strings that may contain tokens.
      logger.log(
        JSON.stringify({
          requestId,
          method: request.method,
          path: request.path,
          statusCode: response.statusCode,
          durationMs: Number(durationMs.toFixed(1)),
        }),
      );
    });
    next();
  };
}

function parseTrustProxy(value: string): string | number | boolean {
  if (value === 'true') return true;
  if (value === 'false') return false;
  const numericValue = Number(value);
  return Number.isInteger(numericValue) && numericValue >= 0
    ? numericValue
    : value;
}
