const REQUIRED_VARIABLES = [
  'MONGODB_URI',
  'JWT_ACCESS_SECRET',
  'JWT_REFRESH_SECRET',
  'JWT_EMAIL_VERIFY_SECRET',
  'BACKEND_BASE_URL',
] as const;

const JWT_SECRETS = [
  'JWT_ACCESS_SECRET',
  'JWT_REFRESH_SECRET',
  'JWT_EMAIL_VERIFY_SECRET',
  'JWT_RESET_PASSWORD_SECRET',
] as const;

const POSITIVE_INTEGER_VARIABLES = [
  'PORT',
  'RATE_LIMIT_DEFAULT_TTL',
  'RATE_LIMIT_DEFAULT_LIMIT',
  'OTP_FORGOT_PASSWORD_EXPIRE',
  'EXTERNAL_REQUEST_TIMEOUT_MS',
  'AI_DAILY_GUEST_LIMIT',
  'AI_DAILY_USER_LIMIT',
  'GUEST_PLAN_TTL_HOURS',
] as const;

const DURATION_VARIABLES = [
  'JWT_ACCESS_EXPIRED',
  'JWT_REFRESH_EXPIRED',
  'JWT_EMAIL_VERIFY_EXPIRE',
  'JWT_RESET_PASSWORD_EXPIRE',
] as const;

export function validateEnvironment(
  environment: Record<string, unknown>,
): Record<string, unknown> {
  const missing = REQUIRED_VARIABLES.filter((key) => {
    const value = environment[key];
    return typeof value !== 'string' || value.trim().length === 0;
  });

  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(', ')}`,
    );
  }

  const nodeEnvironment = stringValue(environment.NODE_ENV) ?? 'development';
  if (!['development', 'test', 'production'].includes(nodeEnvironment)) {
    throw new Error('NODE_ENV must be development, test, or production');
  }

  validateUrl(environment, 'BACKEND_BASE_URL');
  validateMongoUri(environment.MONGODB_URI);
  validateOptionalUrls(environment.FRONTEND_URL, 'FRONTEND_URL');
  validatePositiveIntegers(environment);
  validateDurations(environment);

  if (nodeEnvironment === 'production') {
    validateProductionEnvironment(environment);
  }
  return environment;
}

function validateProductionEnvironment(
  environment: Record<string, unknown>,
): void {
  const required = [
    'FRONTEND_URL',
    'GEMINI_API_KEY',
    'MAIL_FROM',
    'JWT_RESET_PASSWORD_SECRET',
    'AI_QUOTA_SALT',
  ];
  const missing = required.filter((key) => !stringValue(environment[key]));
  if (missing.length > 0) {
    throw new Error(
      `Missing production environment variables: ${missing.join(', ')}`,
    );
  }

  const weakSecrets = JWT_SECRETS.filter((key) => {
    const value = stringValue(environment[key]);
    return !value || value.length < 32;
  });
  if (weakSecrets.length > 0) {
    throw new Error(
      `JWT secrets must contain at least 32 characters: ${weakSecrets.join(', ')}`,
    );
  }

  const configuredSecrets = JWT_SECRETS.map((key) =>
    stringValue(environment[key]),
  );
  if (new Set(configuredSecrets).size !== configuredSecrets.length) {
    throw new Error('JWT secrets must be different for each token purpose');
  }

  const hasResend = Boolean(stringValue(environment.RESEND_API_KEY));
  const hasSmtp = ['MAIL_HOST', 'MAIL_USER', 'MAIL_PASS'].every((key) =>
    Boolean(stringValue(environment[key])),
  );
  if (!hasResend && !hasSmtp) {
    throw new Error(
      'Configure RESEND_API_KEY or MAIL_HOST, MAIL_USER and MAIL_PASS in production',
    );
  }
}

function validateMongoUri(value: unknown): void {
  const uri = stringValue(value);
  if (!uri || !/^mongodb(?:\+srv)?:\/\//.test(uri)) {
    throw new Error('MONGODB_URI must be a valid MongoDB connection URI');
  }
}

function validateUrl(environment: Record<string, unknown>, key: string): void {
  const value = stringValue(environment[key]);
  if (!value) return;
  try {
    new URL(value);
  } catch {
    throw new Error(`${key} must be a valid URL`);
  }
}

function validateOptionalUrls(value: unknown, key: string): void {
  const configured = stringValue(value);
  if (!configured) return;
  for (const url of configured.split(',').map((item) => item.trim())) {
    try {
      new URL(url);
    } catch {
      throw new Error(`${key} contains an invalid URL: ${url}`);
    }
  }
}

function validatePositiveIntegers(environment: Record<string, unknown>): void {
  for (const key of POSITIVE_INTEGER_VARIABLES) {
    const value = stringValue(environment[key]);
    if (value === undefined || value === '') continue;
    const numericValue = Number(value);
    if (!Number.isInteger(numericValue) || numericValue <= 0) {
      throw new Error(`${key} must be a positive integer`);
    }
  }
}

function validateDurations(environment: Record<string, unknown>): void {
  for (const key of DURATION_VARIABLES) {
    const value = stringValue(environment[key]);
    if (!value) continue;
    if (!/^\d+(?:ms|s|m|h|d|w|y)$/.test(value)) {
      throw new Error(`${key} must be a duration such as 15m, 7d, or 1h`);
    }
  }
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' ? value.trim() : undefined;
}
