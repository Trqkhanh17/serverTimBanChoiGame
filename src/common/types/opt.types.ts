import { Otp } from '@/modules/otp/schemas/otp.schema';

export interface CreateOtpInput {
  userId: string;
  purpose: OtpPurpose;
  expiresInMinutes: number;
}
export type OtpDocument = Otp & Document;

export type OtpPurpose = 'reset_phone' | 'reset_password';
