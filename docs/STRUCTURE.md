# Project Structure & Architecture

## Folder Structure

```
src/
├── auth/           # Authentication Module
│   ├── dto/        # Data Transfer Objects for Auth (Login, Register, etc.)
│   ├── passport/   # Passport strategies (JWT, Local) and Guards
│   ├── auth.controller.ts # Handles HTTP requests for /auth
│   ├── auth.module.ts     # Auth module definition
│   └── auth.service.ts    # Business logic for Auth
│
├── common/         # Shared Resources
│   ├── decorators/ # Custom decorators (e.g. @User())
│   ├── filters/    # Exception filters
│   ├── helpers/    # Utility functions (hash, compare, etc.)
│   └── types/      # TypeScript type definitions
│
├── mail/           # Mail Module
│   ├── templates/  # Handlebars email templates
│   └── mail.service.ts # Service for sending emails
│
├── modules/        # Feature Modules
│   ├── users/      # User Management (CRUD, Profile)
│   ├── match-search/ # Matchmaking Logic (Currently Boilerplate)
│   ├── game-profile/ # Game Profile Management (Currently Boilerplate)
│   ├── friend/     # Friend System (Currently Boilerplate)
│   └── otp/        # OTP Management
│
├── app.module.ts   # Root Module (Imports all other modules)
└── main.ts         # Application Entry Point
```

## Architecture Overview

- **Modular Monolith:** The application is structured into modules based on features (`auth`, `users`, `match-search`).
- **Dependency Injection:** Uses NestJS's DI system to manage dependencies between services and controllers.
- **Data Access:** Uses Mongoose to interact with MongoDB. Schemas are defined in each module (e.g., `users/schemas/user.schema.ts`).
- **Authentication Flow:**
  1.  User logs in via `/auth/login`.
  2.  Server validates credentials and issues an `access_token` (short-lived) and `refresh_token` (long-lived).
  3.  Client sends `access_token` in `Authorization` header for protected routes.
  4.  When `access_token` expires, client uses `refresh_token` at `/auth/refresh` to get a new pair.
