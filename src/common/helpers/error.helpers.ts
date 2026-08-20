export const getErrorStack = (error: unknown): string | undefined =>
  error instanceof Error ? error.stack : undefined;
