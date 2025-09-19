import bcrypt from 'bcrypt';

const saltRounds = 10;
export const hashHelper = async (input: string) => {
  try {
    return await bcrypt.hash(input, saltRounds);
  } catch (error) {
    console.log(error);
  }
};
export const compareHelper = async (
  input: string | null,
  hashInput: string | null,
) => {
  try {
    return await bcrypt.compare(input, hashInput);
  } catch (error) {
    console.log(error);
  }
};
