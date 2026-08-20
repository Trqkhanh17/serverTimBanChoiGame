import { validateEnvironment } from './environment.validation';

describe('validateEnvironment', () => {
  const validEnvironment = {
    MONGODB_URI: 'mongodb://localhost/test',
    JWT_ACCESS_SECRET: 'access-secret',
    JWT_REFRESH_SECRET: 'refresh-secret',
    JWT_EMAIL_VERIFY_SECRET: 'email-secret',
    BACKEND_BASE_URL: 'http://localhost:8080',
  };

  it('returns a valid environment unchanged', () => {
    expect(validateEnvironment(validEnvironment)).toBe(validEnvironment);
  });

  it('lists all missing required variables', () => {
    expect(() => validateEnvironment({})).toThrow(
      /MONGODB_URI, JWT_ACCESS_SECRET, JWT_REFRESH_SECRET, JWT_EMAIL_VERIFY_SECRET, BACKEND_BASE_URL/,
    );
  });

  it('rejects malformed MongoDB URIs and numeric settings', () => {
    expect(() =>
      validateEnvironment({ ...validEnvironment, MONGODB_URI: 'http://db' }),
    ).toThrow(/MongoDB connection URI/);
    expect(() =>
      validateEnvironment({ ...validEnvironment, AI_DAILY_GUEST_LIMIT: '1.5' }),
    ).toThrow(/positive integer/);
  });

  it('requires strong isolated secrets in production', () => {
    expect(() =>
      validateEnvironment({
        ...validEnvironment,
        NODE_ENV: 'production',
        FRONTEND_URL: 'https://example.com',
        GEMINI_API_KEY: 'gemini-key',
        MAIL_FROM: 'noreply@example.com',
        RESEND_API_KEY: 'resend-key',
        JWT_RESET_PASSWORD_SECRET: 'reset-secret',
        AI_QUOTA_SALT: 'quota-salt',
      }),
    ).toThrow(/at least 32 characters/);
  });
});
