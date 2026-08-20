import {
  type ValidationArguments,
  ValidatorConstraint,
  type ValidatorConstraintInterface,
} from 'class-validator';

interface TripDurationInput {
  days?: number;
  nights?: number;
}

@ValidatorConstraint({ name: 'nightsFitTripDuration', async: false })
export class NightsFitTripDurationConstraint
  implements ValidatorConstraintInterface
{
  validate(value: unknown, arguments_: ValidationArguments): boolean {
    if (value === undefined || value === null) return true;
    const input = arguments_.object as TripDurationInput;
    return (
      typeof value === 'number' &&
      Number.isInteger(value) &&
      typeof input.days === 'number' &&
      value >= 0 &&
      value <= input.days
    );
  }

  defaultMessage(): string {
    return 'Số đêm không được lớn hơn số ngày';
  }
}
