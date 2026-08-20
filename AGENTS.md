# AI Agent Guidelines – AI Travel & Outing Planner Server

## 1. Project Overview & Tech Stack
- **Role:** Backend API for AI Travel & Outing Planning platform (`ai-travel-planner-server`).
- **Framework:** NestJS 11 (Express platform), TypeScript 5.7+ (Node.js >= 24).
- **Database:** MongoDB via `@nestjs/mongoose` and Mongoose 8.
- **AI Engine:** Google Gemini via `@google/genai` (Structured JSON Schema).
- **Validation:** `class-validator`, `class-transformer`, `zod` for AI output runtime validation.
- **Security:** Passport (JWT Access, JWT Refresh, Local), Bcrypt, Throttler, Helmet.
- **Mail:** Nodemailer (SMTP) / Resend API.
- **Package Manager:** `pnpm` (or `npm`).

---

## 2. Architecture & Directory Structure
The codebase follows Clean Architecture with high encapsulation:
- `src/config/`: Environment variable validation (`environment.validation.ts`) and global application setup (`application.setup.ts`).
- `src/common/`: Shared `BaseRepository`, types, helpers, and custom validators.
- `src/auth/`: Specialized sub-services (`AuthTokenService`, `EmailVerificationService`, `PasswordResetService`), Passport guards & strategies.
- `src/modules/users/`: User entity management and profiles (`UsersService`, `UsersRepository`, `UserSchema`).
- `src/modules/otp/`: OTP generation, hashing, verification, and cleanup (`OtpService`, `OtpRepository`, `OtpSchema`).
- `src/modules/trip-planner/`: AI itinerary generation, quota management `AiQuotaService`, prompt builder, response schema, and post-validation with Zod.
- `src/mail/`: Email delivery service for verification and OTP via SMTP or Resend.
- `docs/`: Comprehensive documentation (`PRD.md`, `SRS.md`, `API.md`, `STRUCTURE.md`).

---

## 3. Strict Development & Security Rules

### 🔐 Authentication & Security (Auth)
1. **Sensitive Data Hashing:**
   - Passwords, Refresh Tokens, OTP codes, and `verifyJti` **must be hashed with bcrypt** before being persisted to MongoDB.
2. **Token Revocation (`refreshTokenVersion`):**
   - When changing password, resetting password, or logging out, call `usersService.revokeAllRefreshTokens` / `removeRefreshToken` to increment `refreshTokenVersion`, immediately invalidating all previous tokens across all devices.
3. **Response Security:**
   - Never expose `password`, `refreshToken`, `guestTokenHash`, or `userId` in JSON responses sent to clients (configured via Mongoose `select: false` and schema `toJSON.transform`).
4. **Optional Authentication:**
   - For public endpoints serving both guest visitors and authenticated users, use `OptionalJwtAccessGuard`.

### ✈️ Trip Planning & AI (Trip Planner)
1. **Prompt Creation & Gemini AI Invocation:**
   - Always use Structured JSON Schema (`buildTripPlanResponseSchema`) with `@google/genai` SDK.
   - All user input parameters must be enclosed within `<trip_criteria>` tags and treated strictly as data, not system instructions.
2. **Post-Validation of AI Results:**
   - AI outputs must be validated with `validateGeneratedTripPlan` (Zod) to ensure: correct number of days, sequential day order, budget within maximum limit, and component costs matching `totalEstimated` within allowable tolerance.
3. **AI Quota Management:**
   - User identity / Guest IP must be hashed via HMAC-SHA256 (`AiQuotaService`), verifying quota before calling Gemini (20 requests/day for User, 5 requests/day for Guest IP).

---

## 4. Coding & Clean Code Standards
- **File Naming:** Use `kebab-case` naming convention (e.g. `trip-plan-prompt.builder.ts`, `auth-response.dto.ts`).
- **DTO Validation:** Every incoming endpoint payload must declare a DTO with `class-validator` decorators, with `whitelist: true` and `forbidNonWhitelisted: true` enabled.
- **Database Operations:** Use Repository Pattern extending `BaseRepository`.
- **Error Handling:** Use standard NestJS HTTP exceptions (`BadRequestException`, `UnauthorizedException`, `ForbiddenException`, `NotFoundException`).
- **Logging:** Use NestJS `Logger`, never use `console.log`.

---

## 5. Development & Testing Commands
Before completing any task, always run the following commands to verify:
- **Build:** `pnpm build` (or `npm run build`)
- **Lint:** `pnpm run lint` (or `npm run lint`)
- **Unit Test:** `pnpm test` (or `npm test`)
- **E2E Test:** `pnpm run test:e2e` (or `npm run test:e2e`)

---

## 6. Commit Message Convention
Follow **Conventional Commits**:
- `feat: <description>` (New feature)
- `fix: <description>` (Bug fix)
- `refactor: <description>` (Code refactoring)
- `test: <description>` (Adding or updating tests)
- `docs: <description>` (Documentation update)
