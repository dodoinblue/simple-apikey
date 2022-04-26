import crypto from "crypto";
import { API_KEY_ALGORITHM } from "./constants";

export class ApiKeyGenerator {
  constructor(
    private readonly masterSecret: string // Base64 string
  ) {
    if (!this.masterSecret || this.masterSecret.length === 0) {
      throw new Error("Master secret is required");
    }
  }

  private encrypt(text: string, ivBase64: string = undefined) {
    const iv = ivBase64
      ? Buffer.from(ivBase64, "base64")
      : crypto.randomBytes(16);
    const key = Buffer.from(this.masterSecret, "base64");
    let cipher = crypto.createCipheriv(API_KEY_ALGORITHM, Buffer.from(key), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return {
      iv: iv.toString("base64"),
      encryptedData: encrypted.toString("base64"),
    };
  }

  public createApiKey(orgId: string) {
    const dateTimeUtc = new Date().toISOString();
    const date = dateTimeUtc.substring(0, 10);

    const { iv, encryptedData } = this.encrypt(
      `${date}#${orgId}`,
      this.masterSecret
    );
    const secretBuffer = Buffer.concat([
      Buffer.from(date),
      Buffer.from(iv, "base64"),
      Buffer.from(encryptedData, "base64"),
    ]);
    return {
      orgId,
      issuedAt: dateTimeUtc,
      apiKey: iv,
      apiSecret: secretBuffer.toString("base64"),
    };
  }
}
