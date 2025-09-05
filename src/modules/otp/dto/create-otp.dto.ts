import type { OtpPurpose } from '@/common/types/opt.types';
import { IsNotEmpty } from 'class-validator';

export class CreateOtpDto {
  @IsNotEmpty()
  userId: string;

  @IsNotEmpty()
  otpExpiresAt: Date;

  @IsNotEmpty()
  purpose: OtpPurpose;
}
