export interface CreateOtpInput {
  userId: string;
  purpose: OtpPurpose;
  otpCode: string;
  expiresInMinutes: number;
}

export interface VerifyOtpInput {
  userId: string;
  otpCode: string;
  purpose: OtpPurpose;
}

export type OtpPurpose = 'reset_phone' | 'forgot_password';
