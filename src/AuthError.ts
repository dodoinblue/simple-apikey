export class AuthError extends Error {
  errCode: string;

  constructor(message) {
    super(message);
    this.name = 'AuthError';
    this.errCode = 'AuthError';

    // https://stackoverflow.com/a/41102306/2320096
    Object.setPrototypeOf(this, AuthError.prototype);
  }
}
