# AI Travel & Outing Planner Server

Backend server for **AI Travel & Outing Planner**, built with [NestJS](https://nestjs.com/), MongoDB, and Google Gemini AI SDK.

## 🚀 Key Features

- **AI Trip Planning:** Automatically analyzes budget, group size, origin, preferences, and generates detailed itineraries (Morning/Afternoon/Evening), recommended dining spots, attractions, and budget allocation using Google Gemini.
- **Structured Outputs:** Uses JSON Schema to ensure 100% structured and predictable AI responses.
- **History & Sharing:** Stores trip plans in MongoDB, supporting history pagination, claiming guest plans, and toggling public/private sharing.
- **Authentication & Security:** JWT (Access & Refresh Tokens), Bcrypt hashing, Passport, Token Revocation, and Throttler Rate Limiting.
- **Mailing System:** Nodemailer SMTP or Resend HTTP API for email verification and OTP password recovery.
- **Daily AI Quota:** Protects Gemini API consumption by enforcing daily usage quotas per user and per guest IP via HMAC-SHA256 tracking.

## 🛠️ Technologies

- **Framework:** NestJS v11
- **Runtime:** Node.js 24 LTS
- **Language:** TypeScript v5.7
- **Database:** MongoDB (via Mongoose 8)
- **AI Engine:** Google Gemini AI (`@google/genai`)
- **Authentication:** JWT (Access & Refresh Token), Passport
- **Email:** Nodemailer (SMTP) or Resend HTTP API
- **Rate Limiting:** `@nestjs/throttler`

## 📦 Installation & Setup

1. **Clone repository:**

   ```bash
   git clone https://github.com/Trqkhanh17/ai-travel-planner-server.git
   cd ai-travel-planner-server
   ```

2. **Install dependencies:**

   ```bash
   npm ci
   # or
   pnpm install
   ```

3. **Configure environment (.env):**

   ```bash
   cp .env.example .env
   ```

   Update the required variables in `.env`:

   - `MONGODB_URI`: MongoDB connection string
   - `GEMINI_API_KEY`: API Key from [Google AI Studio](https://aistudio.google.com/)
   - `GEMINI_MODEL`: default `gemini-3.5-flash-lite` for optimal cost and performance
   - `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`
   - `JWT_EMAIL_VERIFY_SECRET`, `JWT_RESET_PASSWORD_SECRET`
   - `BACKEND_BASE_URL`: Base URL of the backend service

4. **Run server:**

   ```bash
   # Development
   npm run start:dev

   # Production build
   npm run build
   npm run start:prod

   # Quality & Tests
   npm run lint
   npm test
   npm run test:e2e
   ```

## 📚 API Overview

Base URL: `/api/v1`

### 1. AI Trip Planner

- `POST /trip-planner/generate`: Generate AI trip plan (supports both guests and authenticated users).
- `GET /trip-planner/my-trips`: Get user's trip history with pagination.
- `GET /trip-planner/public`: Get publicly shared trip plans with pagination.
- `GET /trip-planner/quota`: Check remaining AI generation quota for user or IP.
- `GET /trip-planner/:id`: Get detailed trip plan by ID.
- `POST /trip-planner/:id/claim`: Claim a guest trip plan into user account.
- `PATCH /trip-planner/:id/share`: Toggle public sharing status.
- `DELETE /trip-planner/:id`: Delete a trip plan (owner or guest with token).

### 2. Authentication & Users

- `POST /auth/register`: Register new account (requires email verification).
- `GET /auth/verify-email`: Verify account via one-time email link.
- `POST /auth/resend-verification`: Resend verification email.
- `POST /auth/login`: Login and receive access & refresh tokens.
- `GET /auth/profile`: Get current user profile.
- `PATCH /auth/profile`: Update user profile.
- `POST /auth/refresh`: Refresh access token using refresh token.
- `PATCH /auth/change-password`: Change password (authenticated).
- `POST /auth/forgot-password`: Request 6-digit OTP for password reset.
- `POST /auth/forgot-password-verify`: Verify OTP and receive short-lived reset token.
- `PATCH /auth/change-password-forgot`: Reset password using reset token.
- `DELETE /auth/logout`: Logout and revoke refresh token.

## 📖 Documentation

- [Documentation Index](docs/README.md)
- [Product Requirements Document (PRD)](docs/PRD.md)
- [Software Requirements Specification (SRS)](docs/SRS.md)
- [API Documentation](docs/API.md)
- [Project Structure & Architecture](docs/STRUCTURE.md)

Health check: `GET /api/v1/health`

Swagger/OpenAPI documentation: `GET /api/v1/docs`

Guest plans are private by default, expire automatically based on configured TTL, and are managed via a single-use guest management token.
