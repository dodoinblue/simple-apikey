export class AuthError extends Error {
  errCode: string;

  constructor(message: string = "Invalid API key") {
    super(message);
    this.errCode = "AuthError";
  }
}
