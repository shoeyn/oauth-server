import { describe, it, expect } from "vitest";
import { generateECKeyPair } from "../lib/crypto";

describe("generateECKeyPair", () => {
  it("should generate an ECDSA P-256 key pair with publicKey and privateKey", async () => {
    const keyPair = await generateECKeyPair();

    expect(keyPair).toHaveProperty("publicKey");
    expect(keyPair).toHaveProperty("privateKey");

    expect(keyPair.publicKey).toMatch(/^-----BEGIN PUBLIC KEY-----/);
    expect(keyPair.publicKey).toMatch(/-----END PUBLIC KEY-----$/);

    expect(keyPair.privateKey).toMatch(/^-----BEGIN PRIVATE KEY-----/);
    expect(keyPair.privateKey).toMatch(/-----END PRIVATE KEY-----$/);
  });
});
