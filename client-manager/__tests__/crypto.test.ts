import { describe, it, expect } from "vitest";
import { generateRSAKeyPair } from "../lib/crypto";

describe("generateRSAKeyPair", () => {
  it("should generate an RSA key pair with publicKey and privateKey", async () => {
    const keyPair = await generateRSAKeyPair();

    expect(keyPair).toHaveProperty("publicKey");
    expect(keyPair).toHaveProperty("privateKey");

    expect(keyPair.publicKey).toMatch(/^-----BEGIN PUBLIC KEY-----/);
    expect(keyPair.publicKey).toMatch(/-----END PUBLIC KEY-----$/);

    expect(keyPair.privateKey).toMatch(/^-----BEGIN PRIVATE KEY-----/);
    expect(keyPair.privateKey).toMatch(/-----END PRIVATE KEY-----$/);
  });
});
