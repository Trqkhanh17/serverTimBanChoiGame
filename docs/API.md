# API Documentation

Base URL: `/api/v1`

---

## 1. AI Trip Planner (`/trip-planner`)

### 1.1. Tạo kế hoạch du lịch bằng AI

- **URL:** `/trip-planner/generate`
- **Method:** `POST`
- **Headers:** `Authorization: Bearer <access_token>` _(Tùy chọn)_
- Có access token: kế hoạch được gắn với user và mặc định riêng tư.
- Không có access token: kế hoạch là riêng tư, tự hết hạn và chỉ mở được bằng `X-Guest-Token`.
- **Body:**
  ```json
  {
    "budget": 5000000,
    "budgetType": "total",
    "numberOfPeople": 4,
    "originLocation": "TP. Hồ Chí Minh",
    "destinationPreference": "Vũng Tàu",
    "tripStyles": ["Nghỉ dưỡng", "Ẩm thực hải sản", "Check-in sống ảo"],
    "days": 2,
    "nights": 1,
    "transportationPreference": "Xe máy / Ô tô tự lái",
    "specialNotes": "Muốn ăn hải sản tươi ngon giá hợp lý và cafe ngắm hoàng hôn"
  }
  ```
- **Response (201):**
  ```json
  {
    "message": "Tạo kế hoạch du lịch thành công!",
    "data": {
      "_id": "67b6a1e8c9d...",
      "destination": {
        "name": "Vũng Tàu",
        "tagline": "Chuyến đi biển 2N1Đ thư giãn và thưởng thức hải sản",
        "reason": "Phù hợp hoàn hảo với ngân sách 5 triệu cho 4 người xuất phát từ TP.HCM"
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
          "title": "Khám phá biển và ẩm thực chợ đêm",
          "morning": {
            "time": "07:30 - 11:30",
            "activity": "Di chuyển từ TP.HCM đến Vũng Tàu, ăn sáng bánh khọt Cô Ba",
            "places": ["Bánh khọt Cô Ba Vũng Tàu"],
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
    "guest_manage_token": "token-chỉ-trả-một-lần-cho-guest"
  }
  ```

### 1.2. Lấy danh sách chuyến đi của User

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

### 1.3. Danh sách lịch trình công khai

- **URL:** `/trip-planner/public?page=1&limit=10`
- **Method:** `GET`
- **Auth:** Không yêu cầu

### 1.4. Xem chi tiết kế hoạch theo ID

- **URL:** `/trip-planner/:id`
- **Method:** `GET`
- **Headers:** `Authorization: Bearer <access_token>` cho owner, hoặc `X-Guest-Token` cho kế hoạch guest.
- **Response (200):**
  ```json
  {
    "data": { ...trip_plan_detail }
  }
  ```

### 1.5. Nhận kế hoạch guest vào tài khoản

- **URL:** `/trip-planner/:id/claim`
- **Method:** `POST`
- **Headers:** `Authorization: Bearer <access_token>` và `X-Guest-Token: <guest_manage_token>`

### 1.6. Xem quota AI

- **URL:** `/trip-planner/quota`
- **Method:** `GET`
- **Auth:** Tùy chọn

### 1.7. Bật/tắt chia sẻ cho bạn bè

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

### 1.8. Xóa kế hoạch du lịch

- **URL:** `/trip-planner/:id`
- **Method:** `DELETE`
- **Headers:** `Authorization: Bearer <access_token>` cho owner, hoặc `X-Guest-Token` cho guest.
- **Response (200):**
  ```json
  {
    "message": "Đã xóa kế hoạch du lịch thành công."
  }
  ```

---

## 2. Authentication (`/auth`)

### 2.1. Đăng ký

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
- Tài khoản phải xác minh email trước khi đăng nhập. Endpoint này không cấp token.

### 2.2. Đăng nhập

- **URL:** `/auth/login`
- **Method:** `POST`
- **Body:**
  ```json
  {
    "email": "user@example.com",
    "password": "password123"
  }
  ```

### 2.3. Lấy thông tin cá nhân

- **URL:** `/auth/profile`
- **Method:** `GET`
- **Headers:** `Authorization: Bearer <access_token>`

### 2.4. Cập nhật thông tin cá nhân

- **URL:** `/auth/profile`
- **Method:** `PATCH`
- **Headers:** `Authorization: Bearer <access_token>`
- **Body:** Có thể gửi một hoặc nhiều trường `name`, `phone`, `avatarUrl`, `bio`, `gender`, `birthDate`.

### 2.5. Cấp lại access_token

- **URL:** `/auth/refresh`
- **Method:** `POST`
- **Headers:** `Authorization: Bearer <refresh_token>`

### 2.6. Đổi mật khẩu

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

### 2.7. Đăng xuất

- **URL:** `/auth/logout`
- **Method:** `DELETE`
- **Headers:** `Authorization: Bearer <refresh_token>`

### 2.8. Xác minh và gửi lại email

- `GET /auth/verify-email?token=<verification_token>`
- `POST /auth/resend-verification` với body `{ "email": "user@example.com" }`

### 2.9. Quên mật khẩu

1. `POST /auth/forgot-password`
   ```json
   { "email": "user@example.com" }
   ```
2. `POST /auth/forgot-password-verify`
   ```json
   { "email": "user@example.com", "otpCode": "123456" }
   ```
   Response trả về `reset_token` tồn tại trong thời gian ngắn.
3. `PATCH /auth/change-password-forgot`
   ```json
   {
     "resetToken": "<reset_token>",
     "newPassword": "newpassword123",
     "confirmPassword": "newpassword123"
   }
   ```

Reset token chỉ dùng được một lần. Đổi mật khẩu hoặc đăng xuất sẽ thu hồi các access/refresh token cũ.

---

## 3. System

- `GET /health`: Trả về trạng thái API, kết nối MongoDB và cấu hình Gemini.
