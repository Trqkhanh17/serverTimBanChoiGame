# Product Requirements Document (PRD)

## AI Travel & Outing Planner

| Attribute      | Value                                                  |
| -------------- | ------------------------------------------------------ |
| Version        | 1.0                                                    |
| Status         | Baseline according to implemented product              |
| Updated Date   | 2026-08-20                                             |
| Scope          | Backend API `ai-travel-planner-server`                 |
| Target Readers | Product Owner, Business Analyst, Developer, QA, DevOps |

## 1. Product Summary

AI Travel & Outing Planner is a backend service that empowers users to create customized travel and outing plans based on budget, group size, duration, origin, destination preference, and travel styles. The system leverages Google Gemini to generate structured output, subsequently persisting the itinerary to MongoDB for retrieval, sharing, or deletion.

The product supports two usage modes:
- **Guest Users:** Can generate itineraries without creating an account. Plans are private by default, time-limited with TTL, and managed via a single-use guest management token.
- **Registered Users:** Can create persistent private plans, manage personal history, and toggle public sharing.

In addition to itinerary generation, the platform provides full account lifecycle management: registration, email verification, authentication, token refresh, profile management, password changes, OTP-based password recovery, and secure logout.

## 2. Background and Problem Statement

Travelers frequently face difficulty aggregating information across multiple disparate sources to answer:
- Where can I go with my current budget?
- How should the budget be allocated across transport, lodging, meals, and entertainment?
- How should morning, afternoon, and evening activities be organized for geographic coherence?
- Where to eat, what to visit, and what precautions should be taken?
- How can the generated plan be stored or shared with travel companions?

Manual planning is time-consuming, prone to budget overruns, and often yields unrealistic itineraries. The product resolves these pain points by standardizing inputs, utilizing AI synthesis, and returning a consistent JSON structure for client applications.

## 3. Product Vision

Become a fast, intuitive, and cost-effective travel planning engine that transforms initial user criteria into an actionable itinerary within minutes.

## 4. Product Goals

### 4.1. Core Goals
- Generate comprehensive travel itineraries from concise user inputs.
- Ensure total AI estimated cost never exceeds the user's specified maximum budget.
- Enable immediate guest access without upfront registration.
- Enable registered users to save, view, share, and delete personal trip plans.
- Secure user accounts via email verification, JWTs, token revocation, one-time OTPs, and rate limiting.
- Maintain minimal operational cost through MongoDB, Gemini Flash-Lite, and lightweight containerization.

### 4.2. Proposed Success Metrics

| Code   | Metric                                | Initial Target                                 |
| ------ | ------------------------------------- | ---------------------------------------------- |
| KPI-01 | Trip Generation Request Success Rate  | ≥ 95% under normal Gemini/MongoDB availability |
| KPI-02 | Budget Compliance Rate                | 100% post-backend validation                   |
| KPI-03 | Duration (Days) Accuracy Rate         | 100% post-backend validation                   |
| KPI-04 | Generation Latency (P95)              | ≤ 30s (dependent on Gemini API)                |
| KPI-05 | Non-AI API Response Time (P95)        | ≤ 1s under standard load                       |
| KPI-06 | CI Pipeline Pass Rate                 | 100% before PR merge                           |
| KPI-07 | High/Critical Known Vulnerabilities   | 0 at release                                   |

## 5. Target Personas

### 5.1. Guest Visitors
Users wishing to quickly test itinerary generation without signing up.
- Needs: Input criteria, receive itinerary, view public trips, manage/delete plan using ID and guest token.
- Limitations: No personal history dashboard, cannot toggle public sharing without claiming into an account, plans subject to TTL expiration.

### 5.2. Registered Users
Users seeking long-term plan management and privacy control.
- Needs: Secure login, save private itineraries, paginated history (`my-trips`), toggle public sharing, delete own trips, manage profile and credentials.

### 5.3. Operations & Admins
The `admin` role exists in the schema for future administrative dashboards. Operations are presently handled via server logs, MongoDB management, and environment configurations.

## 6. Product Scope

### 6.1. In-Scope (Current Baseline)
- Local account registration via email and password.
- Single-use JWT email verification.
- Account state-agnostic resend verification endpoint.
- Login issuing access and refresh tokens.
- Access token refresh flow.
- Token revocation on password change, password reset, and logout (`refreshTokenVersion`).
- Profile view and update endpoints.
- OTP password recovery (6-digit one-time code + short-lived reset token).
- Gemini structured output trip planning.
- Backend duration and budget compliance validation.
- MongoDB persistence for guest and user plans.
- Paginated personal history and public itinerary feeds.
- Access control for private itineraries.
- Public sharing toggle and owner-based plan deletion.
- System health checks (`/health`), Swagger/OpenAPI documentation (`/docs`).
- Rate limiting, DTO validation, Helmet, CORS, and request logging.
- Unit tests, E2E API tests, Docker setup, and GitHub Actions CI.

### 6.2. Out-of-Scope (Current Phase)
- Native mobile or web frontend implementations.
- Direct booking / payments for flights, hotels, or restaurants.
- Real-time pricing synchronization with external OTAs.
- Turn-by-turn GPS navigation or live distance calculations.
- Social OAuth logins (Google, Facebook, Apple).
- Real-time collaborative editing.
- Comments, reviews, ratings, and social follows.
- Push notifications, SMS, or trip reminder calendars.
- Admin portal APIs.
- Multi-currency conversion (VNĐ standard).

## 7. Business Rules

| Code  | Rule                                                                                               |
| ----- | -------------------------------------------------------------------------------------------------- |
| BR-01 | Email addresses must be trimmed and converted to lowercase prior to storage or lookup.              |
| BR-02 | Email and username must be unique across the platform.                                            |
| BR-03 | New accounts are inactive (`isActive = false`) and cannot log in until email is verified.          |
| BR-04 | Banned accounts cannot log in, refresh tokens, or access protected resources.                     |
| BR-05 | Email verification tokens are single-use; requesting a new link invalidates previous tokens.       |
| BR-06 | Passwords must be 8–20 characters and stored strictly as bcrypt hashes.                            |
| BR-07 | Refresh tokens must be stored strictly as bcrypt hashes. Raw tokens are never persisted.          |
| BR-08 | Password change, password reset, or logout increments `refreshTokenVersion`, invalidating tokens.  |
| BR-09 | Only one active OTP per user per purpose is valid; requesting a new OTP deletes prior unused OTPs. |
| BR-10 | OTPs consist of 6 numeric digits, are hashed, time-limited, and single-use.                        |
| BR-11 | Forgot-password and resend-verification endpoints must return neutral responses (no email leak).   |
| BR-12 | Input budget must be between 100,000 VNĐ and 1,000,000,000 VNĐ.                                    |
| BR-13 | Budget can be provided as `total` or `per_person`.                                                 |
| BR-14 | Group size: 1–100 people; Days: 1–14 days; Nights: 0–14 nights.                                    |
| BR-15 | If nights are omitted, system defaults to `max(0, days - 1)`.                                      |
| BR-16 | If destination preference is omitted, AI selects the optimal destination based on budget.         |
| BR-17 | Generated itinerary must contain exactly the requested number of days.                             |
| BR-18 | `totalEstimated` must be finite, non-negative, and not exceed the total group budget.              |
| BR-19 | Registered user itineraries are private by default.                                                |
| BR-20 | Guest itineraries are private by default, have TTL, and require a valid guest token to access.     |
| BR-21 | Only the owner can toggle public sharing or delete a trip plan.                                    |
| BR-22 | Private plans can only be accessed by the owner with a valid access token or guest manage token.   |
| BR-23 | Public plans can be viewed without authentication.                                                 |
| BR-24 | `userId` and `guestTokenHash` must never be exposed in client-facing JSON responses.               |

## 8. Core User Journeys

### 8.1. Guest Trip Planning
1. Guest enters budget, group size, origin, duration, and preferences.
2. Backend validates input and verifies daily guest quota.
3. Gemini synthesizes structured itinerary.
4. Backend verifies day count and budget constraints.
5. Plan is saved with `userId = null`, `isPublic = false`, and expiration TTL.
6. API returns itinerary details along with single-use `guest_manage_token`.

### 8.2. Registration & Email Verification
1. User submits email, username, password, and name.
2. Backend verifies uniqueness, creates inactive user, hashes single-use verification JTI, and dispatches email.
3. User opens verification link.
4. Backend validates token and JTI, sets `isActive = true`, and clears JTI.
5. User logs in.

### 8.3. Authenticated Trip Planning & Management
1. User logs in to receive access and refresh tokens.
2. User generates plan with access token. Plan is linked to user account.
3. User views paginated personal plans at `/trip-planner/my-trips`.
4. User can toggle sharing at `/trip-planner/:id/share` to make it visible in public feed.
5. User can delete owned plans.

### 8.4. Password Recovery
1. User submits email via `/auth/forgot-password`.
2. API responds with neutral message. If user exists, generates 6-digit OTP and emails it.
3. User verifies OTP at `/auth/forgot-password-verify` and receives a short-lived `reset_token`.
4. User submits new password with reset token at `/auth/change-password-forgot`.
5. Backend updates password, increments `refreshTokenVersion`, and invalidates all existing tokens.

## 9. Epics & Product Requirements

### EPIC-01: Identity & Access Management
- PR-01: Users can register with a unique email and username.
- PR-02: Email verification is required before login.
- PR-03: Users can resend verification emails securely.
- PR-04: Active users can authenticate and receive access/refresh tokens.
- PR-05: Users can refresh access tokens using valid refresh tokens.
- PR-06: Users can logout, revoking the active refresh token.
- PR-07: Inactive or banned accounts are blocked from protected endpoints.

### EPIC-02: Profile & Credentials
- PR-08: Users can view their own profile.
- PR-09: Users can update allowed profile fields (name, phone, bio, avatar, gender, birth date).
- PR-10: Authenticated users can change password after validating old password.
- PR-11: Users can recover forgotten passwords via OTP and reset token.
- PR-12: All prior tokens are revoked upon password alteration.

### EPIC-03: AI Trip Planning
- PR-13: Both guests and authenticated users can generate trip plans.
- PR-14: Supports total or per-person budget inputs.
- PR-15: AI outputs destination info, budget breakdown, daily itineraries, recommended spots, and travel tips.
- PR-16: Backend rejects AI results violating day count or budget limits.
- PR-17: Stores both input criteria and generated plan.

### EPIC-04: History & Sharing
- PR-18: Users can view paginated personal trip history.
- PR-19: Public trip plans can be viewed by anyone with pagination.
- PR-20: Owners can toggle public/private status of plans.
- PR-21: Owners and authorized guests can delete plans.
- PR-22: Non-owners cannot access private plans.

### EPIC-05: System Reliability & Quality
- PR-23: Provides `/health` check endpoint.
- PR-24: Enforces request validation and rate limiting.
- PR-25: Automated CI runs unit tests, linter, E2E tests, and build verification.

## 10. Product Acceptance Criteria

### 10.1. Authentication
- Duplicate email/username registration is blocked with 409 Conflict.
- Unverified accounts cannot authenticate (400 Bad Request).
- Verification links cannot be reused.
- Invalid or revoked refresh tokens are rejected with 401 Unauthorized.

### 10.2. Trip Planning
- Invalid payload is rejected before reaching Gemini.
- Saved plans contain destination, budget breakdown, itinerary, spots, and tips.
- Number of itinerary days matches requested duration.
- Total cost does not exceed budget limit.
- `userId` is never leaked in response JSON.

## 11. Known Constraints & Assumptions
- Information generated by AI (prices, hours, addresses) is for reference.
- One active refresh token is tracked per user account.
- Rate limiting is in-memory for single-instance deployments (can scale to Redis).
- MongoDB and Gemini API keys are mandatory external dependencies.

## 12. Related Documents
- [SRS – Software Requirements Specification](./SRS.md)
- [API Documentation](./API.md)
- [Project Structure & Architecture](./STRUCTURE.md)
