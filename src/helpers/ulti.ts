import bcrypt from 'bcrypt';

const saltRounds = 10;
export const hashPasswordHelper = async (plainPassword: string) => {
  try {
    return await bcrypt.hash(plainPassword, saltRounds);
  } catch (error) {
    console.log(error);
  }
};
export const comparePasswordHelper = async (
  plainPassword: string | null,
  hashPassword: string | null,
) => {
  try {
    return await bcrypt.compare(plainPassword, hashPassword);
  } catch (error) {
    console.log(error);
  }
};
