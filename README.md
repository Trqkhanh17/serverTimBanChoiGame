# Server Tìm Bạn Chơi Game (AOV Squad Finder)

Backend server for the AOV Squad Finder application, built with [NestJS](https://nestjs.com/) and MongoDB.

## 🚀 Technologies

- **Framework:** NestJS v11
- **Language:** TypeScript v5.7
- **Database:** MongoDB (via Mongoose)
- **Authentication:** JWT (Access Token & Refresh Token), Passport
- **Email:** Nodemailer (SMTP)
- **Rate Limiting:** @nestjs/throttler

## 🛠️ Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/Trqkhanh17/serverTimBanChoiGame.git
    cd serverTimBanChoiGame
    ```

2.  **Install dependencies:**

    ```bash
    npm install
    # or
    pnpm install
    ```

3.  **Environment Configuration:**
    Copy `.env.example` to `.env` and update the values:

    ```bash
    cp .env.example .env
    ```

    _See [Environment Variables](#environment-variables) below for details._

4.  **Run the application:**

    ```bash
    # development
    npm run start

    # watch mode
    npm run start:dev

    # production mode
    npm run start:prod
    ```

## 🔑 Environment Variables

| Variable                     | Description                   | Default / Example               |
| :--------------------------- | :---------------------------- | :------------------------------ |
| `PORT`                       | Server port                   | `8080`                          |
| `MONGODB_URI`                | MongoDB connection string     | `mongodb://localhost:27017/aov` |
| `JWT_ACCESS_SECRET`          | Secret for access token       | `secret`                        |
| `JWT_ACCESS_EXPIRED`         | Access token expiration       | `15m`                           |
| `JWT_REFRESH_SECRET`         | Secret for refresh token      | `secret`                        |
| `JWT_REFRESH_EXPIRED`        | Refresh token expiration      | `7d`                            |
| `JWT_EMAIL_VERIFY_SECRET`    | Secret for email verification | `secret`                        |
| `JWT_EMAIL_VERIFY_EXPIRE`    | Email verification expiration | `15m`                           |
| `OTP_FORGOT_PASSWORD_EXPIRE` | OTP expiration time           | `5m`                            |
| `MAIL_HOST`                  | SMTP Host                     | `smtp.gmail.com`                |
| `MAIL_USER`                  | SMTP Username                 | `user@gmail.com`                |
| `MAIL_PASS`                  | SMTP Password                 | `password`                      |

## 📚 Documentation

Detailed documentation is available in the `docs/` directory:

- [**API Documentation**](docs/API.md): Detailed description of all API endpoints.
- [**Project Structure**](docs/STRUCTURE.md): Explanation of the folder structure and architecture.

## 🤝 Contributing

1.  Fork the repository
2.  Create your feature branch (`git checkout -b feature/amazing-feature`)
3.  Commit your changes (`git commit -m 'Add some amazing feature'`)
4.  Push to the branch (`git push origin feature/amazing-feature`)
5.  Open a Pull Request
