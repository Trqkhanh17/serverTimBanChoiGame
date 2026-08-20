# AI Travel & Outing Planner Server

Backend server for **AI Travel & Outing Planner**, built with [NestJS](https://nestjs.com/), MongoDB, and Google Gemini AI SDK.

## 🚀 Key Features

- **AI Trip Planning:** Tự động phân tích ngân sách, số người, sở thích và đề xuất địa điểm, lịch trình chi tiết (Sáng/Trưa/Tối), quán ăn đặc sản và dự toán chi tiêu bằng Google Gemini 2.0 Flash.
- **Structured Outputs:** Sử dụng JSON Schema để đảm bảo dữ liệu AI trả về chuẩn xác 100%.
- **Lịch sử & Chia sẻ:** Lưu trữ lịch trình vào MongoDB, hỗ trợ xem lại và bật/tắt chia sẻ cho bạn bè.
- **Authentication & Security:** JWT (Access Token & Refresh Token), Passport, Rate Limiting.
- **Mailing System:** Nodemailer với template Handlebars cho xác thực email / đổi mật khẩu.

## 🛠️ Technologies

- **Framework:** NestJS v11
- **Language:** TypeScript v5.7
- **Database:** MongoDB (via Mongoose)
- **AI Engine:** Google Gemini AI (`@google/genai`)
- **Authentication:** JWT (Access Token & Refresh Token), Passport
- **Email:** Nodemailer (SMTP)
- **Rate Limiting:** @nestjs/throttler

## 📦 Installation & Setup

1. **Clone repository:**
   ```bash
   git clone https://github.com/Trqkhanh17/serverTimBanChoiGame.git
   cd serverTimBanChoiGame
   ```

2. **Cài đặt dependencies:**
   ```bash
   pnpm install
   # hoặc npm install
   ```

3. **Cấu hình môi trường (.env):**
   ```bash
   cp .env.example .env
   ```
   Cập nhật các biến quan trọng trong file `.env`:
   - `MONGODB_URI`: Đường dẫn kết nối MongoDB
   - `GEMINI_API_KEY`: API Key lấy từ [Google AI Studio](https://aistudio.google.com/)
   - `GEMINI_MODEL`: `gemini-2.0-flash`
   - `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`

4. **Chạy server:**
   ```bash
   # Development
   npm run start:dev

   # Production build
   npm run build
   npm run start:prod
   ```

## 📚 API Overview

Base URL: `/api/v1`

### 1. AI Trip Planner
- `POST /trip-planner/generate`: Sinh kế hoạch du lịch & ăn chơi bằng AI (hỗ trợ cả khách vãng lai và user đăng nhập).
- `GET /trip-planner/my-trips`: Lấy danh sách lịch sử chuyến đi của user.
- `GET /trip-planner/:id`: Xem chi tiết kế hoạch theo ID.
- `PATCH /trip-planner/:id/share`: Bật/tắt chế độ chia sẻ công khai cho bạn bè.
- `DELETE /trip-planner/:id`: Xóa kế hoạch của user.

### 2. Authentication & Users
- `POST /auth/register`: Đăng ký tài khoản.
- `POST /auth/login`: Đăng nhập lấy access_token và refresh_token.
- `GET /auth/profile`: Lấy thông tin cá nhân.
- `PATCH /auth/profile`: Cập nhật thông tin cá nhân.
- `POST /auth/refresh`: Cấp mới access_token.
- `POST /auth/forgot-password`: Gửi OTP quên mật khẩu.
- `PATCH /auth/change-password`: Đổi mật khẩu.
- `DELETE /auth/logout`: Đăng xuất.

Chi tiết xem tại [API Documentation](docs/API.md).
