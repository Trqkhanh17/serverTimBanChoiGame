# AI Agent Guidelines – AI Travel & Outing Planner Server

> Detailed configuration is centrally managed in [AGENTS.md](../AGENTS.md).

## Quick Summary
- **Tech Stack:** NestJS 11, TypeScript (Node >= 24), MongoDB (Mongoose 8), Google Gemini `@google/genai`, Zod, Passport JWT.
- **Security:** Bcrypt hashing for password, refresh token, OTP, and verifyJti. `refreshTokenVersion` revocation on password change & logout.
- **Trip Planner:** Structured JSON Schema + Zod post-validation + HMAC-SHA256 Daily Quota.
- **Commands:** `pnpm build`, `pnpm run lint`, `pnpm test`, `pnpm run test:e2e`.
