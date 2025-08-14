import { LoginRequestDto } from '@/auth/dto/login.Dto ';
import { PartialType } from '@nestjs/mapped-types';

export class UpdateAuthDto extends PartialType(LoginRequestDto) {}
