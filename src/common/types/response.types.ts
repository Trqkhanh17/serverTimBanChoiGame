export type ApiSuccess<T> = {
  success: true;
  statusCode: 200;
  data: T;
};
