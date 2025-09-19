import { Otp } from '@/modules/otp/schemas/otp.schema';

export interface CreateOtpInput {
  userId: string;
  purpose: OtpPurpose;
  otpCode: string;
  expiresInMinutes: number;
}
export interface verifyOtpInput {
  userId: string;
  otpCode: string;
  purpose: OtpPurpose;
}
export type OtpDocument = Otp & Document;

export type OtpPurpose = 'reset_phone' | 'forgot_password';
