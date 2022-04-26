export class AuthError extends Error {
  errCode: string;

  constructor(message = 'Invalid API key') {
    super(message);
    this.errCode = 'AuthError';
  }
}
