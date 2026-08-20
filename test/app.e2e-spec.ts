/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { MongoMemoryServer } from 'mongodb-memory-server';
import request from 'supertest';
import { App } from 'supertest/types';
import { MailService } from './../src/mail/mail.service';
import { API_PREFIX } from './../src/common/constants/api.constants';
import { GeminiAiService } from './../src/modules/trip-planner/services/gemini-ai.service';
import type { CreateTripPlanDto } from './../src/modules/trip-planner/dto/create-trip-plan.dto';
import type { GeneratedTripPlanResult } from './../src/modules/trip-planner/dto/trip-plan-response.dto';
import { configureApplication } from './../src/config/application.setup';

describe('API (e2e)', () => {
  let app: INestApplication<App>;
  let mongoServer: MongoMemoryServer;

  const sendVerifyEmailUser = jest.fn<Promise<void>, [string, string]>();
  const sendOtpForgotPassword = jest.fn<Promise<void>, [string, string]>();

  const createAiResult = (dto: CreateTripPlanDto): GeneratedTripPlanResult => ({
    destination: {
      name: dto.destinationPreference ?? 'Vũng Tàu',
      tagline: 'Chuyến đi thử nghiệm',
      reason: 'Phù hợp ngân sách',
    },
    budgetBreakdown: {
      totalEstimated: dto.budget,
      costPerPerson: dto.budget / dto.numberOfPeople,
      transportation: dto.budget * 0.2,
      accommodation: dto.budget * 0.2,
      foodAndDining: dto.budget * 0.3,
      entertainmentAndTickets: dto.budget * 0.2,
      contingency: dto.budget * 0.1,
      currency: 'VNĐ',
    },
    itinerary: Array.from({ length: dto.days }, (_, index) => ({
      day: index + 1,
      title: `Ngày ${index + 1}`,
      morning: {
        time: '08:00 - 11:00',
        activity: 'Tham quan',
        places: ['Điểm A'],
        estimatedCost: 100_000,
      },
      afternoon: {
        time: '13:00 - 17:00',
        activity: 'Khám phá',
        places: ['Điểm B'],
        estimatedCost: 100_000,
      },
      evening: {
        time: '18:00 - 21:00',
        activity: 'Ăn tối',
        places: ['Quán C'],
        estimatedCost: 100_000,
      },
    })),
    recommendedSpots: { foodAndDrink: [], attractions: [] },
    travelTips: ['Mang theo giấy tờ tùy thân'],
  });

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    Object.assign(process.env, {
      MONGODB_URI: mongoServer.getUri(),
      JWT_ACCESS_SECRET: 'e2e-access-secret-at-least-32-characters',
      JWT_ACCESS_EXPIRED: '15m',
      JWT_REFRESH_SECRET: 'e2e-refresh-secret-at-least-32-characters',
      JWT_REFRESH_EXPIRED: '7d',
      JWT_EMAIL_VERIFY_SECRET: 'e2e-email-secret-at-least-32-characters',
      JWT_EMAIL_VERIFY_EXPIRE: '15m',
      JWT_RESET_PASSWORD_SECRET: 'e2e-reset-secret-at-least-32-characters',
      JWT_RESET_PASSWORD_EXPIRE: '10m',
      OTP_FORGOT_PASSWORD_EXPIRE: '5',
      BACKEND_BASE_URL: 'http://localhost:8080',
      RATE_LIMIT_DEFAULT_TTL: '1',
      RATE_LIMIT_DEFAULT_LIMIT: '1000',
      AI_DAILY_GUEST_LIMIT: '1',
      AI_DAILY_USER_LIMIT: '20',
      AI_QUOTA_SALT: 'e2e-quota-salt-at-least-32-characters',
      GUEST_PLAN_TTL_HOURS: '72',
      EXTERNAL_REQUEST_TIMEOUT_MS: '25000',
      GEMINI_API_KEY: 'e2e-fake-key',
      MAIL_FROM: 'test@example.com',
    });
    const { AppModule } = (await import(
      './../src/app.module'
    )) as typeof import('./../src/app.module');

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(MailService)
      .useValue({ sendVerifyEmailUser, sendOtpForgotPassword })
      .overrideProvider(GeminiAiService)
      .useValue({
        generateTripPlan: jest
          .fn()
          .mockImplementation((dto: CreateTripPlanDto) =>
            Promise.resolve(createAiResult(dto)),
          ),
      })
      .compile();

    app = moduleFixture.createNestApplication();
    configureApplication(app);
    await app.init();
  }, 120_000);

  afterAll(async () => {
    await app.close();
    await mongoServer.stop();
  });

  it('serves the API index and health endpoint', async () => {
    await request(app.getHttpServer())
      .get(`/${API_PREFIX}`)
      .expect(200)
      .expect((response) => {
        expect(response.text).toContain('Available API Endpoints');
      });

    const health = await request(app.getHttpServer())
      .get(`/${API_PREFIX}/health`)
      .expect(200);
    expect(health.body).toMatchObject({
      status: 'ok',
      database: 'connected',
      ai: 'configured',
    });
  });

  it('registers, verifies, logs in, refreshes and updates a user', async () => {
    const register = await request(app.getHttpServer())
      .post(`/${API_PREFIX}/auth/register`)
      .send({
        email: 'owner@example.com',
        username: 'owner_user',
        password: 'Password123',
        name: 'Owner',
      })
      .expect(201);
    expect(register.body.access_token).toBeUndefined();
    expect(register.body.user.isActive).toBe(false);

    await request(app.getHttpServer())
      .post(`/${API_PREFIX}/auth/login`)
      .send({ email: 'owner@example.com', password: 'Password123' })
      .expect(400);

    await request(app.getHttpServer())
      .post(`/${API_PREFIX}/auth/resend-verification`)
      .send({ email: 'owner@example.com' })
      .expect(202);
    expect(sendVerifyEmailUser.mock.calls).toHaveLength(2);

    const verifyUrl = sendVerifyEmailUser.mock.calls.at(-1)?.[1];
    expect(verifyUrl).toBeDefined();
    const verifyToken = new URL(verifyUrl!).searchParams.get('token');
    await request(app.getHttpServer())
      .get(`/${API_PREFIX}/auth/verify-email`)
      .query({ token: verifyToken })
      .expect(200);
    await request(app.getHttpServer())
      .get(`/${API_PREFIX}/auth/verify-email`)
      .query({ token: verifyToken })
      .expect(400);

    const login = await request(app.getHttpServer())
      .post(`/${API_PREFIX}/auth/login`)
      .send({ email: 'owner@example.com', password: 'Password123' })
      .expect(200);
    expect(login.body.access_token).toEqual(expect.any(String));
    expect(login.body.refresh_token).toEqual(expect.any(String));

    const accessToken = login.body.access_token as string;
    const refreshToken = login.body.refresh_token as string;
    const profile = await request(app.getHttpServer())
      .get(`/${API_PREFIX}/auth/profile`)
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);
    expect(profile.body.email).toBe('owner@example.com');

    const updated = await request(app.getHttpServer())
      .patch(`/${API_PREFIX}/auth/profile`)
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ bio: 'Travel lover', gender: 'male' })
      .expect(200);
    expect(updated.body.bio).toBe('Travel lover');

    const refreshed = await request(app.getHttpServer())
      .post(`/${API_PREFIX}/auth/refresh`)
      .set('Authorization', `Bearer ${refreshToken}`)
      .expect(200);
    expect(refreshed.body.access_token).toEqual(expect.any(String));
  });

  it('resets a forgotten password with a one-time OTP and reset token', async () => {
    await request(app.getHttpServer())
      .post(`/${API_PREFIX}/auth/forgot-password`)
      .send({ email: 'owner@example.com' })
      .expect(202);

    const otpCode = sendOtpForgotPassword.mock.calls.at(-1)?.[1];
    expect(otpCode).toMatch(/^\d{6}$/);

    await request(app.getHttpServer())
      .post(`/${API_PREFIX}/auth/forgot-password-verify`)
      .send({ email: 'owner@example.com', otpCode: '000000' })
      .expect(400);

    const verified = await request(app.getHttpServer())
      .post(`/${API_PREFIX}/auth/forgot-password-verify`)
      .send({ email: 'owner@example.com', otpCode })
      .expect(200);
    const resetToken = verified.body.reset_token as string;

    await request(app.getHttpServer())
      .patch(`/${API_PREFIX}/auth/change-password-forgot`)
      .send({
        resetToken,
        newPassword: 'NewPassword123',
        confirmPassword: 'NewPassword123',
      })
      .expect(200);
    await request(app.getHttpServer())
      .patch(`/${API_PREFIX}/auth/change-password-forgot`)
      .send({
        resetToken,
        newPassword: 'AnotherPassword123',
        confirmPassword: 'AnotherPassword123',
      })
      .expect(400);

    await request(app.getHttpServer())
      .post(`/${API_PREFIX}/auth/login`)
      .send({ email: 'owner@example.com', password: 'NewPassword123' })
      .expect(200);
  });

  it('generates, protects, shares, lists and deletes trip plans', async () => {
    const login = await request(app.getHttpServer())
      .post(`/${API_PREFIX}/auth/login`)
      .send({ email: 'owner@example.com', password: 'NewPassword123' })
      .expect(200);
    const accessToken = login.body.access_token as string;

    await request(app.getHttpServer())
      .post(`/${API_PREFIX}/trip-planner/generate`)
      .send({ budget: 1, numberOfPeople: 0, originLocation: '', days: 0 })
      .expect(400);
    await request(app.getHttpServer())
      .post(`/${API_PREFIX}/trip-planner/generate`)
      .send({
        budget: 1_000_000,
        numberOfPeople: 1.5,
        originLocation: 'TP.HCM',
        days: 1.5,
      })
      .expect(400);

    const guestTrip = await request(app.getHttpServer())
      .post(`/${API_PREFIX}/trip-planner/generate`)
      .send({
        budget: 1_000_000,
        numberOfPeople: 2,
        originLocation: 'TP.HCM',
        destinationPreference: 'Vũng Tàu',
        days: 1,
      })
      .expect(201);
    expect(guestTrip.body.data.isPublic).toBe(false);
    const guestTripId = guestTrip.body.data._id as string;
    const guestManageToken = guestTrip.body.guest_manage_token as string;
    expect(guestManageToken).toEqual(expect.any(String));

    await request(app.getHttpServer())
      .post(`/${API_PREFIX}/trip-planner/generate`)
      .send({
        budget: 1_000_000,
        numberOfPeople: 2,
        originLocation: 'TP.HCM',
        days: 1,
      })
      .expect(429);

    await request(app.getHttpServer())
      .get(`/${API_PREFIX}/trip-planner/${guestTripId}`)
      .expect(403);
    await request(app.getHttpServer())
      .get(`/${API_PREFIX}/trip-planner/${guestTripId}`)
      .set('X-Guest-Token', 'wrong-token')
      .expect(403);
    await request(app.getHttpServer())
      .get(`/${API_PREFIX}/trip-planner/${guestTripId}`)
      .set('X-Guest-Token', guestManageToken)
      .expect(200);
    await request(app.getHttpServer())
      .post(`/${API_PREFIX}/trip-planner/${guestTripId}/claim`)
      .set('Authorization', `Bearer ${accessToken}`)
      .set('X-Guest-Token', guestManageToken)
      .expect(201);

    const privateTrip = await request(app.getHttpServer())
      .post(`/${API_PREFIX}/trip-planner/generate`)
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        budget: 2_000_000,
        numberOfPeople: 2,
        originLocation: 'TP.HCM',
        destinationPreference: 'Đà Lạt',
        days: 2,
      })
      .expect(201);
    const privateTripId = privateTrip.body.data._id as string;
    expect(privateTrip.body.data.userId).toBeUndefined();

    await request(app.getHttpServer())
      .get(`/${API_PREFIX}/trip-planner/${privateTripId}`)
      .expect(403);
    await request(app.getHttpServer())
      .get(`/${API_PREFIX}/trip-planner/${privateTripId}`)
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    const myTrips = await request(app.getHttpServer())
      .get(`/${API_PREFIX}/trip-planner/my-trips?page=1&limit=10`)
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);
    expect(myTrips.body).toMatchObject({ total: 2, page: 1, totalPages: 1 });

    await request(app.getHttpServer())
      .patch(`/${API_PREFIX}/trip-planner/${privateTripId}/share`)
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200)
      .expect((response) => expect(response.body.isPublic).toBe(true));

    const publicTrips = await request(app.getHttpServer())
      .get(`/${API_PREFIX}/trip-planner/public?page=1&limit=10`)
      .expect(200);
    expect(publicTrips.body.total).toBe(1);
    expect(publicTrips.body.data[0].userId).toBeUndefined();

    await request(app.getHttpServer())
      .delete(`/${API_PREFIX}/trip-planner/${privateTripId}`)
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);
    await request(app.getHttpServer())
      .get(`/${API_PREFIX}/trip-planner/${privateTripId}`)
      .expect(404);
  });

  it('changes password, revokes old tokens and logs out', async () => {
    const login = await request(app.getHttpServer())
      .post(`/${API_PREFIX}/auth/login`)
      .send({ email: 'owner@example.com', password: 'NewPassword123' })
      .expect(200);
    const accessToken = login.body.access_token as string;

    await request(app.getHttpServer())
      .patch(`/${API_PREFIX}/auth/change-password`)
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        oldPassword: 'NewPassword123',
        newPassword: 'FinalPassword123',
        confirmPassword: 'FinalPassword123',
      })
      .expect(200);
    await request(app.getHttpServer())
      .get(`/${API_PREFIX}/auth/profile`)
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(401);

    const newLogin = await request(app.getHttpServer())
      .post(`/${API_PREFIX}/auth/login`)
      .send({ email: 'owner@example.com', password: 'FinalPassword123' })
      .expect(200);
    const newAccessToken = newLogin.body.access_token as string;
    const newRefreshToken = newLogin.body.refresh_token as string;

    await request(app.getHttpServer())
      .delete(`/${API_PREFIX}/auth/logout`)
      .set('Authorization', `Bearer ${newRefreshToken}`)
      .expect(200);
    await request(app.getHttpServer())
      .get(`/${API_PREFIX}/auth/profile`)
      .set('Authorization', `Bearer ${newAccessToken}`)
      .expect(401);
  });
});
