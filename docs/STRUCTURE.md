# Project Structure & Architecture

## Folder Structure

```
src/
├── auth/                 # Authentication Module (JWT, Passport, Refresh Token)
│   ├── dto/              # Data Transfer Objects for Auth (Login, Register, etc.)
│   ├── passport/         # Passport strategies (JWT, Local) and Guards
│   ├── auth.controller.ts
│   ├── auth.module.ts
│   └── auth.service.ts
│
├── common/               # Shared Resources & Utilities
│   ├── constants/        # System constants (e.g. API_PREFIX)
│   ├── helpers/          # Utility functions (hash, compare, etc.)
│   ├── repositories/     # Generic abstract repository
│   └── types/            # TypeScript type definitions
│
├── mail/                 # Email Delivery Module (Nodemailer + Handlebars)
│   ├── templates/        # Email templates
│   └── mail.service.ts
│
├── modules/              # Core Feature Modules
│   ├── trip-planner/     # 🚀 AI Travel & Outing Planner Module
│   │   ├── dto/          # CreateTripPlanDto, GeneratedTripPlanResult
│   │   ├── schemas/      # TripPlan MongoDB Schema
│   │   ├── services/     # GeminiAiService, TripPlannerService
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

- **Modular Architecture:** Hệ thống được chia tách thành các module độc lập theo tính năng (`auth`, `users`, `trip-planner`).
- **AI Integration (Google Gemini SDK):** Tích hợp Google GenAI SDK với cơ chế **JSON Schema Structured Output** giúp AI phản hồi dữ liệu cấu trúc chặt chẽ, không bị lỗi cú pháp.
- **Data Persistence:** Sử dụng MongoDB và Mongoose để lưu trữ thông tin người dùng và các kế hoạch du lịch phức tạp dạng JSON lồng nhau (nested document).
