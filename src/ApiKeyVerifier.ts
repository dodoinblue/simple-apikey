import crypto from 'crypto';
import { AuthError } from './AuthError';
import { API_KEY_ALGORITHM } from './constants';

export class ApiKeyVerifier {
  constructor(
    private readonly masterSecret: string, // Base64 string
    private readonly masterSecretPublishedDate: string, // YYYY-MM-DD format
    private readonly secondaryMasterSecret: string = undefined, // Base64 string
    private readonly validApiKeys: string[] = []
  ) {
    if (!this.masterSecret || this.masterSecret.length === 0) {
      throw new Error('ApiVerifier not properly set up');
    }
  }

  /**
   *
   * @param date date in YYYY-MM-DD format
   */
  private chooseMasterSecret(date: string): string {
    let secret;
    if (this.masterSecretPublishedDate) {
      if (date < this.masterSecretPublishedDate) {
        secret = this.secondaryMasterSecret;
      } else {
        secret = this.masterSecret;
      }
    } else {
      secret = this.masterSecret;
    }
    if (!secret || secret.length === 0) {
      throw new AuthError('Invalid APA key');
    }
    return secret;
  }

  private decrypt(encryptedText: string, masterSecretBase64: string, ivBase64: string) {
    const iv = Buffer.from(ivBase64, 'base64');
    const encryptedTextBuf = Buffer.from(encryptedText, 'base64');
    const key = Buffer.from(masterSecretBase64, 'base64');

    return this.decryptBuffer(encryptedTextBuf, key, iv);
  }

  private decryptBuffer(encryptedBuf: Buffer, key: Buffer, iv: Buffer) {
    const decipher = crypto.createDecipheriv(API_KEY_ALGORITHM, Buffer.from(key), iv);
    let decrypted = decipher.update(encryptedBuf);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  }

  public validateApiSecret(apiSecret: string): string {
    const secretBuf = Buffer.from(apiSecret, 'base64');
    const date = secretBuf.slice(0, 10).toString();
    const iv = secretBuf.slice(10, 26);
    const encryptedData = secretBuf.slice(26);

    if (!this.validApiKeys.includes(iv.toString('base64'))) {
      throw new AuthError('Invalid API key');
    }

    const masterSecret = this.chooseMasterSecret(date);
    const key = Buffer.from(masterSecret, 'base64');
    const decryptedData = this.decryptBuffer(encryptedData, key, iv);

    const [decryptedDate, orgId] = decryptedData.split('#');
    if (decryptedDate !== date) {
      throw new AuthError('Invalid API key');
    }
    return orgId;
  }
}
