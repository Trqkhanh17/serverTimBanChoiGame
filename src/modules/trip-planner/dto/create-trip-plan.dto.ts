import {
  IsArray,
  IsEnum,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';

export enum BudgetType {
  TOTAL = 'total',
  PER_PERSON = 'per_person',
}

export class CreateTripPlanDto {
  @IsNumber()
  @IsNotEmpty()
  @Min(100000, { message: 'Ngân sách tối thiểu là 100.000 VNĐ' })
  @Type(() => Number)
  budget: number;

  @IsOptional()
  @IsEnum(BudgetType, {
    message: 'budgetType phải là "total" hoặc "per_person"',
  })
  budgetType?: BudgetType = BudgetType.TOTAL;

  @IsNumber()
  @IsNotEmpty()
  @Min(1, { message: 'Số lượng người tối thiểu là 1' })
  @Max(100, { message: 'Số lượng người tối đa là 100' })
  @Type(() => Number)
  numberOfPeople: number;

  @IsString()
  @IsNotEmpty({ message: 'Vui lòng cung cấp điểm xuất phát' })
  originLocation: string;

  @IsOptional()
  @IsString()
  destinationPreference?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tripStyles?: string[] = ['Nghỉ dưỡng', 'Ẩm thực'];

  @IsNumber()
  @IsNotEmpty()
  @Min(1, { message: 'Số ngày tối thiểu là 1' })
  @Max(14, { message: 'Số ngày tối đa là 14' })
  @Type(() => Number)
  days: number;

  @IsOptional()
  @IsNumber()
  @Min(0)
  @Max(14)
  @Type(() => Number)
  nights?: number;

  @IsOptional()
  @IsString()
  transportationPreference?: string;

  @IsOptional()
  @IsString()
  specialNotes?: string;
}
