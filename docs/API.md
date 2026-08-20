# API Documentation

Base URL: `/api/v1`

---

## 1. AI Trip Planner (`/trip-planner`)

### 1.1. Tạo kế hoạch du lịch bằng AI
- **URL:** `/trip-planner/generate`
- **Method:** `POST`
- **Headers:** `Authorization: Bearer <access_token>` *(Tùy chọn - nếu có sẽ tự động lưu vào tài khoản)*
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
    }
  }
  ```

### 1.2. Lấy danh sách chuyến đi của User
- **URL:** `/trip-planner/my-trips`
- **Method:** `GET`
- **Headers:** `Authorization: Bearer <access_token>`
- **Response (200):**
  ```json
  {
    "total": 3,
    "data": [ ... ]
  }
  ```

### 1.3. Xem chi tiết kế hoạch theo ID
- **URL:** `/trip-planner/:id`
- **Method:** `GET`
- **Response (200):**
  ```json
  {
    "data": { ...trip_plan_detail }
  }
  ```

### 1.4. Bật/tắt chia sẻ cho bạn bè
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

### 1.5. Xóa kế hoạch du lịch
- **URL:** `/trip-planner/:id`
- **Method:** `DELETE`
- **Headers:** `Authorization: Bearer <access_token>`
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

### 2.2. Đăng nhập
- **URL:** `/auth/login`
- **Method:** `POST`
- **Body:**
  ```json
  {
    "username": "myusername",
    "password": "password123"
  }
  ```

### 2.3. Lấy thông tin cá nhân
- **URL:** `/auth/profile`
- **Method:** `GET`
- **Headers:** `Authorization: Bearer <access_token>`

### 2.4. Cấp lại access_token
- **URL:** `/auth/refresh`
- **Method:** `POST`
- **Headers:** `Authorization: Bearer <refresh_token>`

### 2.5. Đổi mật khẩu
- **URL:** `/auth/change-password`
- **Method:** `PATCH`
- **Headers:** `Authorization: Bearer <access_token>`
- **Body:**
  ```json
  {
    "oldPassword": "password123",
    "newPassword": "newpassword123",
    "comFirmPassword": "newpassword123"
  }
  ```

### 2.6. Đăng xuất
- **URL:** `/auth/logout`
- **Method:** `DELETE`
- **Headers:** `Authorization: Bearer <refresh_token>`
