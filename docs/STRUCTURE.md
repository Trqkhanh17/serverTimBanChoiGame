# Project Structure & Architecture

## Folder Structure

```
src/
├── auth/                 # Authentication Module (JWT, Passport, Refresh Token)
│   ├── dto/              # Data Transfer Objects for Auth (Login, Register, etc.)
│   ├── passport/         # Passport strategies (JWT, Local) and Guards
│   ├── auth.controller.ts
│   ├── auth.module.ts
│   ├── auth.service.ts
│   └── services/         # Token, email verification, password reset sub-services
│
├── common/               # Shared Resources & Utilities
│   ├── constants/        # System constants (e.g. API_PREFIX)
│   ├── helpers/          # Utility functions (hash, compare, error helpers)
│   ├── repositories/     # Typed BaseRepository for MongoDB operations
│   ├── validators/       # Custom class-validator constraints
│   └── types/            # TypeScript type definitions
│
├── config/               # Environment validation and shared application setup
│
├── mail/                 # Email Delivery Module (SMTP or Resend API)
│   └── mail.service.ts
│
├── modules/              # Core Feature Modules
│   ├── trip-planner/     # 🚀 AI Travel & Outing Planner Module
│   │   ├── dto/          # CreateTripPlanDto, Query DTOs, Response DTOs
│   │   ├── schemas/      # TripPlan, AI quota and runtime response validation
│   │   ├── services/     # Gemini AI, prompt builder, and daily quota service
│   │   ├── trip-planner.controller.ts
│   │   └── trip-planner.module.ts
│   ├── users/            # User Management & Profiles
│   └── otp/              # OTP Generation & Verification
│
├── app.controller.ts     # Root API Directory
├── app.module.ts         # Root AppModule
└── main.ts               # Application Bootstrap
```

## Architecture Overview

- **Modular Architecture:** The system is decomposed into feature-driven, loosely coupled modules (`auth`, `users`, `otp`, `trip-planner`, `mail`).
- **AI Integration (Google Gemini SDK):** Integrates Google GenAI SDK with **JSON Schema Structured Outputs** to guarantee syntactically valid and predictable AI responses.
- **Data Persistence:** Uses MongoDB with Mongoose to store user records, AI quota buckets, and nested trip plans.
- **Production Hardening:** Guest plan management with single-use tokens & TTL, HMAC-SHA256 daily AI quotas, external request timeouts, request ID tracking, security headers (Helmet), compression, and Swagger/OpenAPI documentation.

## Related Documents

- [Product Requirements Document](./PRD.md)
- [Software Requirements Specification](./SRS.md)
- [API Documentation](./API.md)
