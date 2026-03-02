import {
  IsArray,
  IsBoolean,
  IsEnum,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';

export class CreateGameProfileDto {
  @IsNotEmpty()
  @IsString()
  ign: string;

  @IsOptional()
  @IsString()
  rank?: string;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(30)
  level?: number;

  @IsOptional()
  @IsString()
  bio?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  mainPositions?: string[];

  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}
