import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return `
      <h1>Available API Endpoints</h1>
      <p>Base URL: /api/v1</p>
      <ul>
        <li><strong>Auth</strong>
          <ul>
            <li>POST /auth/login</li>
            <li>POST /auth/register</li>
            <li>GET /auth/profile</li>
            <li>PATCH /auth/profile</li>
            <li>POST /auth/refresh</li>
            <li>POST /auth/forgot-password</li>
            <li>PATCH /auth/change-password</li>
            <li>PATCH /auth/change-password-forgot</li>
            <li>POST /auth/forgot-password-verify</li>
            <li>POST /auth/resend-verification</li>
            <li>DELETE /auth/logout</li>
            <li>GET /auth/verify-email</li>
          </ul>
        </li>
        <li><strong>AI Trip Planner</strong>
          <ul>
            <li>POST /trip-planner/generate (Tạo kế hoạch du lịch AI)</li>
            <li>GET /trip-planner/my-trips (Lịch sử chuyến đi của user)</li>
            <li>GET /trip-planner/public (Lịch trình công khai)</li>
            <li>GET /trip-planner/quota (Quota tạo lịch trình)</li>
            <li>GET /trip-planner/:id (Chi tiết kế hoạch)</li>
            <li>POST /trip-planner/:id/claim (Lưu kế hoạch guest vào tài khoản)</li>
            <li>PATCH /trip-planner/:id/share (Bật/tắt chia sẻ cho bạn bè)</li>
            <li>DELETE /trip-planner/:id (Xóa kế hoạch)</li>
          </ul>
        </li>
        <li><strong>System</strong>: GET /health, GET /docs</li>
      </ul>
    `;
  }

  @Get('health')
  getHealth() {
    return this.appService.getHealth();
  }
}
