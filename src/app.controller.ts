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
            <li>DELETE /auth/logout</li>
            <li>GET /auth/verify-email</li>
          </ul>
        </li>
        <li><strong>Friend</strong>
          <ul>
            <li>GET /friend</li>
            <li>POST /friend</li>
            <li>GET /friend/:id</li>
            <li>PATCH /friend/:id</li>
            <li>DELETE /friend/:id</li>
          </ul>
        </li>
        <li><strong>Game Profile</strong>
          <ul>
            <li>GET /game-profile</li>
            <li>POST /game-profile</li>
            <li>GET /game-profile/:id</li>
            <li>PATCH /game-profile/:id</li>
            <li>DELETE /game-profile/:id</li>
          </ul>
        </li>
        <li><strong>Match Search</strong>
          <ul>
            <li>GET /match-search</li>
            <li>POST /match-search</li>
            <li>GET /match-search/:id</li>
            <li>PATCH /match-search/:id</li>
            <li>DELETE /match-search/:id</li>
          </ul>
        </li>
      </ul>
    `;
  }
}
