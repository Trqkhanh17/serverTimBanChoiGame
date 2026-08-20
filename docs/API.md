# API Documentation

Base URL: `/api/v1`

---

## 1. AI Trip Planner (`/trip-planner`)

### 1.1. Generate AI Trip Plan

- **URL:** `/trip-planner/generate`
- **Method:** `POST`
- **Headers:** `Authorization: Bearer <access_token>` _(Optional)_
  - With access token: The trip plan is permanently linked to the user account (private by default).
  - Without access token: The trip plan is created as a temporary guest plan (expires after configured TTL, accessible only via `X-Guest-Token`).
- **Body:**
  ```json
  {
    "budget": 5000000,
    "budgetType": "total",
    "numberOfPeople": 4,
    "originLocation": "Ho Chi Minh City",
    "destinationPreference": "Vung Tau",
    "tripStyles": ["Relaxation", "Seafood Dining", "Sightseeing"],
    "days": 2,
    "nights": 1,
    "transportationPreference": "Self-drive Motorbike / Car",
    "specialNotes": "Fresh seafood at reasonable prices and sunset coffee"
  }
  ```
- **Response (201):**
  ```json
  {
    "message": "Tạo kế hoạch du lịch thành công!",
    "data": {
      "_id": "67b6a1e8c9d...",
      "destination": {
        "name": "Vung Tau",
        "tagline": "2D1N coastal relaxation and seafood experience",
        "reason": "Perfect fit for a 5,000,000 VND budget for 4 people departing from HCMC"
      },
      "budgetBreakdown": {
        "totalEstimated": 4800000,
        "costPerPerson": 1200000,
        "transportation": 800000,
        "accommodation": 1200000,
        "foodAndDining": 2000000,
        "entertainmentAndTickets": 500000,
        "contingency": 300000,
        "currency": "VNĐ"
      },
      "itinerary": [
        {
          "day": 1,
          "title": "Beach exploration and night market culinary tour",
          "morning": {
            "time": "07:30 - 11:30",
            "activity": "Travel from HCMC to Vung Tau, breakfast at Co Ba banh khot",
            "places": ["Co Ba Vung Tau Banh Khot"],
            "estimatedCost": 250000
          },
          "afternoon": { ... },
          "evening": { ... }
        }
      ],
      "recommendedSpots": {
        "foodAndDrink": [ ... ],
        "attractions": [ ... ]
      },
      "travelTips": [ ... ],
      "isPublic": false
    },
    "guest_manage_token": "single-use-token-for-guests"
  }
  ```

### 1.2. Get User's Trip History

- **URL:** `/trip-planner/my-trips?page=1&limit=10`
- **Method:** `GET`
- **Headers:** `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "total": 3,
    "page": 1,
    "limit": 10,
    "totalPages": 1,
    "data": [ ... ]
  }
  ```

### 1.3. Get Public Trip Plans

- **URL:** `/trip-planner/public?page=1&limit=10`
- **Method:** `GET`
- **Auth:** Not required (Public)

### 1.4. Get Trip Plan Detail by ID

- **URL:** `/trip-planner/:id`
- **Method:** `GET`
- **Headers:** `Authorization: Bearer <access_token>` for owner, or `X-Guest-Token: <token>` for guest plan.
- **Response (200):**
  ```json
  {
    "data": { ...trip_plan_detail }
  }
  ```

### 1.5. Claim Guest Trip Plan

- **URL:** `/trip-planner/:id/claim`
- **Method:** `POST`
- **Headers:** `Authorization: Bearer <access_token>` and `X-Guest-Token: <guest_manage_token>`

### 1.6. Check AI Quota Status

- **URL:** `/trip-planner/quota`
- **Method:** `GET`
- **Auth:** Optional (`Authorization: Bearer <access_token>` for user quota, IP for guest quota)

### 1.7. Toggle Public Sharing

- **URL:** `/trip-planner/:id/share`
- **Method:** `PATCH`
- **Headers:** `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "message": "Đã bật chế độ chia sẻ công khai",
    "isPublic": true,
    "data": { ... }
  }
  ```

### 1.8. Delete Trip Plan

- **URL:** `/trip-planner/:id`
- **Method:** `DELETE`
- **Headers:** `Authorization: Bearer <access_token>` for owner, or `X-Guest-Token: <token>` for guest plan.
- **Response (200):**
  ```json
  {
    "message": "Đã xóa kế hoạch du lịch thành công."
  }
  ```

---

## 2. Authentication (`/auth`)

### 2.1. Register

- **URL:** `/auth/register`
- **Method:** `POST`
- **Body:**
  ```json
  {
    "email": "user@example.com",
    "username": "myusername",
    "password": "password123",
    "name": "Nguyen Van A"
  }
  ```
- Newly registered accounts require email verification before login. This endpoint does not issue tokens.

### 2.2. Login

- **URL:** `/auth/login`
- **Method:** `POST`
- **Body:**
  ```json
  {
    "email": "user@example.com",
    "password": "password123"
  }
  ```
- **Response (200):** Returns `access_token`, `refresh_token`, and `user` payload.

### 2.3. Get Profile

- **URL:** `/auth/profile`
- **Method:** `GET`
- **Headers:** `Authorization: Bearer <access_token>`

### 2.4. Update Profile

- **URL:** `/auth/profile`
- **Method:** `PATCH`
- **Headers:** `Authorization: Bearer <access_token>`
- **Body:** Accepts one or more of `name`, `phone`, `avatarUrl`, `bio`, `gender`, `birthDate`.

### 2.5. Refresh Access Token

- **URL:** `/auth/refresh`
- **Method:** `POST`
- **Headers:** `Authorization: Bearer <refresh_token>`

### 2.6. Change Password (Authenticated)

- **URL:** `/auth/change-password`
- **Method:** `PATCH`
- **Headers:** `Authorization: Bearer <access_token>`
- **Body:**
  ```json
  {
    "oldPassword": "password123",
    "newPassword": "newpassword123",
    "confirmPassword": "newpassword123"
  }
  ```

### 2.7. Logout

- **URL:** `/auth/logout`
- **Method:** `DELETE`
- **Headers:** `Authorization: Bearer <refresh_token>`

### 2.8. Email Verification

- `GET /auth/verify-email?token=<verification_token>`: Verifies the email link.
- `POST /auth/resend-verification`: Resends verification link with `{ "email": "user@example.com" }`.

### 2.9. Forgot Password Flow

1. `POST /auth/forgot-password`
   ```json
   { "email": "user@example.com" }
   ```
2. `POST /auth/forgot-password-verify`
   ```json
   { "email": "user@example.com", "otpCode": "123456" }
   ```
   Response returns a short-lived `reset_token`.
3. `PATCH /auth/change-password-forgot`
   ```json
   {
     "resetToken": "<reset_token>",
     "newPassword": "newpassword123",
     "confirmPassword": "newpassword123"
   }
   ```

Changing password or logging out immediately revokes all previously issued tokens via `refreshTokenVersion`.

---

## 3. System

- `GET /health`: Returns service health, database connectivity status, and Gemini configuration status.
- `GET /docs`: Swagger/OpenAPI interactive API documentation.
