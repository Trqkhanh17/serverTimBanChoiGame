export interface AuthUser {
  _id: string;
  email: string;
  name: string;
  username: string;
  isActive: boolean;
  isBanned: boolean;
}

export interface InputChangePasswordAuth {
  newPassword: string;
  oldPassword: string;
  comFirmPassword: string;
  userId: string;
}

// export interface
