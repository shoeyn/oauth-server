export async function generateECKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["sign", "verify"],
  );

  const exportPublicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const exportPrivateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

  const pubB64 = btoa(String.fromCharCode(...new Uint8Array(exportPublicKey)));
  const privB64 = btoa(String.fromCharCode(...new Uint8Array(exportPrivateKey)));

  return {
    publicKey: `-----BEGIN PUBLIC KEY-----\n${pubB64.match(/.{1,64}/g)?.join("\n")}\n-----END PUBLIC KEY-----`,
    privateKey: `-----BEGIN PRIVATE KEY-----\n${privB64.match(/.{1,64}/g)?.join("\n")}\n-----END PRIVATE KEY-----`,
  };
}
