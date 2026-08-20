# AI Travel & Outing Planner Server

Backend server for **AI Travel & Outing Planner**, built with [NestJS](https://nestjs.com/), MongoDB, and Google Gemini AI SDK.

## 🚀 Key Features

- **AI Trip Planning:** Tự động phân tích ngân sách, số người, sở thích và đề xuất địa điểm, lịch trình chi tiết (Sáng/Trưa/Tối), quán ăn đặc sản và dự toán chi tiêu bằng Google Gemini.
- **Structured Outputs:** Sử dụng JSON Schema để đảm bảo dữ liệu AI trả về chuẩn xác 100%.
- **Lịch sử & Chia sẻ:** Lưu trữ lịch trình vào MongoDB, hỗ trợ xem lại và bật/tắt chia sẻ cho bạn bè.
- **Authentication & Security:** JWT (Access Token & Refresh Token), Passport, Rate Limiting.
- **Mailing System:** Nodemailer SMTP hoặc Resend HTTP API cho xác thực email và khôi phục mật khẩu.

## 🛠️ Technologies

- **Framework:** NestJS v11
- **Runtime:** Node.js 24 LTS
- **Language:** TypeScript v5.7
- **Database:** MongoDB (via Mongoose)
- **AI Engine:** Google Gemini AI (`@google/genai`)
- **Authentication:** JWT (Access Token & Refresh Token), Passport
- **Email:** Nodemailer (SMTP) hoặc Resend HTTP API
- **Rate Limiting:** @nestjs/throttler

## 📦 Installation & Setup

1. **Clone repository:**

   ```bash
   git clone https://github.com/Trqkhanh17/ai-travel-planner-server.git
   cd ai-travel-planner-server
   ```

2. **Cài đặt dependencies:**

   ```bash
   npm ci
   ```

3. **Cấu hình môi trường (.env):**

   ```bash
   cp .env.example .env
   ```

   Cập nhật các biến quan trọng trong file `.env`:

   - `MONGODB_URI`: Đường dẫn kết nối MongoDB
   - `GEMINI_API_KEY`: API Key lấy từ [Google AI Studio](https://aistudio.google.com/)
   - `GEMINI_MODEL`: mặc định `gemini-3.5-flash-lite` để ưu tiên free tier và chi phí thấp
   - `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`
   - `JWT_EMAIL_VERIFY_SECRET`, `JWT_RESET_PASSWORD_SECRET`

4. **Chạy server:**

   ```bash
   # Development
   npm run start:dev

   # Production build
   npm run build
   npm run start:prod

   # Kiểm tra chất lượng
   npm run lint
   npm test
   npm run test:e2e
   ```

## 📚 API Overview

Base URL: `/api/v1`

### 1. AI Trip Planner

- `POST /trip-planner/generate`: Sinh kế hoạch du lịch & ăn chơi bằng AI (hỗ trợ cả khách vãng lai và user đăng nhập).
- `GET /trip-planner/my-trips`: Lấy danh sách lịch sử chuyến đi của user.
- `GET /trip-planner/public`: Lấy danh sách lịch trình được chia sẻ công khai.
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
- `POST /auth/forgot-password-verify`: Xác minh OTP và nhận reset token.
- `PATCH /auth/change-password-forgot`: Đặt mật khẩu mới bằng reset token.
- `POST /auth/resend-verification`: Gửi lại email xác minh.
- `PATCH /auth/change-password`: Đổi mật khẩu.
- `DELETE /auth/logout`: Đăng xuất.

## 📖 Documentation

- [Documentation Index](docs/README.md)
- [Product Requirements Document (PRD)](docs/PRD.md)
- [Software Requirements Specification (SRS)](docs/SRS.md)
- [API Documentation](docs/API.md)
- [Project Structure & Architecture](docs/STRUCTURE.md)

Health check: `GET /api/v1/health`.

Swagger/OpenAPI: `GET /api/v1/docs`.

Kế hoạch guest mặc định riêng tư, tự hết hạn sau thời gian cấu hình và được quản lý bằng token chỉ trả một lần. API cũng áp dụng quota tạo lịch trình theo ngày để bảo vệ free tier Gemini.
