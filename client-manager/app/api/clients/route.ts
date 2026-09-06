import { NextResponse } from "next/server";
import { listClients, saveClient } from "@/lib/s3";
import { ClientConfig } from "@/lib/types";

export async function GET() {
  try {
    const clients = await listClients();
    return NextResponse.json(clients);
  } catch (error) {
    return NextResponse.json({ error: (error as Error).message }, { status: 500 });
  }
}

export async function POST(req: Request) {
  try {
    const body = await req.json();

    if (!body.clientId || typeof body.clientId !== "string") {
      return NextResponse.json({ error: "clientId is required" }, { status: 400 });
    }

    if (!body.publicKeyPem || !body.publicKeyPem.includes("BEGIN PUBLIC KEY")) {
      return NextResponse.json({ error: "A valid RSA public key in PEM format is required" }, { status: 400 });
    }

    const client: ClientConfig = {
      clientId: body.clientId.trim(),
      clientName: body.clientName?.trim() || body.clientId.trim(),
      clientAuthenticationMethods: ["private_key_jwt"],
      authorizationGrantTypes: body.authorizationGrantTypes?.length
        ? body.authorizationGrantTypes
        : ["authorization_code", "refresh_token", "client_credentials"],
      redirectUris: Array.isArray(body.redirectUris)
        ? body.redirectUris.map((u: string) => u.trim()).filter(Boolean)
        : [],
      postLogoutRedirectUris: Array.isArray(body.postLogoutRedirectUris)
        ? body.postLogoutRedirectUris.map((u: string) => u.trim()).filter(Boolean)
        : [],
      scopes: Array.isArray(body.scopes) && body.scopes.length > 0
        ? body.scopes
        : ["openid", "profile", "email"],
      requireProofKey: body.requireProofKey !== undefined ? !!body.requireProofKey : true,
      requireAuthorizationConsent: false,
      accessTokenTimeToLiveMinutes: Number(body.accessTokenTimeToLiveMinutes) || 15,
      refreshTokenTimeToLiveDays: Number(body.refreshTokenTimeToLiveDays) || 30,
      publicKeyPem: body.publicKeyPem.trim(),
    };

    await saveClient(client);
    return NextResponse.json(client, { status: 201 });
  } catch (error) {
    return NextResponse.json({ error: (error as Error).message }, { status: 500 });
  }
}
