import {
  IsArray,
  ArrayMaxSize,
  IsEnum,
  IsInt,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  Max,
  MaxLength,
  Min,
  Validate,
} from 'class-validator';
import { Transform, Type } from 'class-transformer';
import { NightsFitTripDurationConstraint } from '@/common/validators/trip.validators';

export enum BudgetType {
  TOTAL = 'total',
  PER_PERSON = 'per_person',
}

export class CreateTripPlanDto {
  @IsNumber({ maxDecimalPlaces: 0 })
  @IsNotEmpty()
  @Min(100000, { message: 'Ngân sách tối thiểu là 100.000 VNĐ' })
  @Max(1_000_000_000, { message: 'Ngân sách tối đa là 1 tỷ VNĐ' })
  @Type(() => Number)
  budget: number;

  @IsOptional()
  @IsEnum(BudgetType, {
    message: 'budgetType phải là "total" hoặc "per_person"',
  })
  budgetType?: BudgetType = BudgetType.TOTAL;

  @IsInt()
  @IsNotEmpty()
  @Min(1, { message: 'Số lượng người tối thiểu là 1' })
  @Max(100, { message: 'Số lượng người tối đa là 100' })
  @Type(() => Number)
  numberOfPeople: number;

  @IsString()
  @IsNotEmpty({ message: 'Vui lòng cung cấp điểm xuất phát' })
  @MaxLength(100)
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim() : value,
  )
  originLocation: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim() : value,
  )
  destinationPreference?: string;

  @IsOptional()
  @IsArray()
  @ArrayMaxSize(10)
  @IsString({ each: true })
  @MaxLength(50, { each: true })
  @Transform(({ value }: { value: unknown }) =>
    Array.isArray(value)
      ? (value as unknown[]).map((item: unknown) =>
          typeof item === 'string' ? item.trim() : item,
        )
      : value,
  )
  tripStyles?: string[] = ['Nghỉ dưỡng', 'Ẩm thực'];

  @IsInt()
  @IsNotEmpty()
  @Min(1, { message: 'Số ngày tối thiểu là 1' })
  @Max(14, { message: 'Số ngày tối đa là 14' })
  @Type(() => Number)
  days: number;

  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(14)
  @Validate(NightsFitTripDurationConstraint)
  @Type(() => Number)
  nights?: number;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim() : value,
  )
  transportationPreference?: string;

  @IsOptional()
  @IsString()
  @MaxLength(1000)
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.trim() : value,
  )
  specialNotes?: string;
}
