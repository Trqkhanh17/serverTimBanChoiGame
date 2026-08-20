import { compare, hash } from 'bcrypt';

const PASSWORD_SALT_ROUNDS = 10;

export const hashPassword = (value: string): Promise<string> =>
  hash(value, PASSWORD_SALT_ROUNDS);

export const comparePassword = (
  value: string | null | undefined,
  hashValue: string | null | undefined,
): Promise<boolean> => {
  if (!value || !hashValue) return Promise.resolve(false);
  return compare(value, hashValue);
};
