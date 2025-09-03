export interface AuthUser {
  _id: string;
  email: string;
  name: string;
  username: string;
  isActive: boolean;
  isBanned: boolean;
}
