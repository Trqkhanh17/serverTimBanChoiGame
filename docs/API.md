# API Documentation

Base URL: `/api/v1`

## Authentication

### Login

- **URL:** `/auth/login`
- **Method:** `POST`
- **Body:**
  ```json
  {
    "username": "user@example.com", // or username
    "password": "yourpassword"
  }
  ```
- **Success Response:**
  - **Code:** 200
  - **Content:**
    ```json
    {
      "message": "Login successful",
      "access_token": "jwt_access_token",
      "refresh_token": "jwt_refresh_token",
      "user": { ...user_details }
    }
    ```

### Register

- **URL:** `/auth/register`
- **Method:** `POST`
- **Body:**
  ```json
  {
    "email": "user@example.com",
    "username": "username",
    "password": "password",
    "name": "Full Name"
  }
  ```
- **Success Response:**
  - **Code:** 201
  - **Content:**
    ```json
    {
      "message": "Account created successfully",
      "access_token": "...",
      "refresh_token": "...",
      "user": { ... }
    }
    ```

### Refresh Token

- **URL:** `/auth/refresh`
- **Method:** `POST`
- **Headers:** `Authorization: Bearer <refresh_token>`
- **Success Response:**
  - **Code:** 200
  - **Content:** `{ "access_token": "new_access_token" }`

### Get Profile

- **URL:** `/auth/profile`
- **Method:** `GET`
- **Headers:** `Authorization: Bearer <access_token>`
- **Success Response:**
  - **Code:** 200
  - **Content:** User object

### Update Profile

- **URL:** `/auth/profile`
- **Method:** `PATCH`
- **Headers:** `Authorization: Bearer <access_token>`
- **Body:**
  ```json
  {
    "name": "New Name",
    "bio": "New Bio",
    "avatarUrl": "http://...",
    "phone": "123456789",
    "gender": "Male",
    "birthDate": "2000-01-01"
  }
  ```

### Forgot Password

- **URL:** `/auth/forgot-password`
- **Method:** `POST`
- **Body:** `{ "email": "user@example.com" }`
- **Description:** Sends an OTP to the user's email.

### Change Password (Logged In)

- **URL:** `/auth/change-password`
- **Method:** `PATCH`
- **Headers:** `Authorization: Bearer <access_token>`
- **Body:**
  ```json
  {
    "oldPassword": "old_password",
    "newPassword": "new_password",
    "confirmPassword": "new_password"
  }
  ```

### Logout

- **URL:** `/auth/logout`
- **Method:** `DELETE`
- **Headers:** `Authorization: Bearer <refresh_token>`

## Users

_(Endpoints currently empty)_

## Match Search

_(Endpoints currently boilerplate)_

- `POST /match-search`: Create match request
- `GET /match-search`: List all requests
- `GET /match-search/:id`: Get details
- `PATCH /match-search/:id`: Update request
- `DELETE /match-search/:id`: Delete request
