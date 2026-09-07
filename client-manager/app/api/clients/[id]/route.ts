import { NextResponse } from "next/server";
import { getClient, saveClient, deleteClient } from "@/lib/clients";
import { ClientConfig } from "@/lib/types";

export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  try {
    const client = await getClient(id);
    if (!client) {
      return NextResponse.json({ error: "Client not found" }, { status: 404 });
    }
    return NextResponse.json(client);
  } catch (error) {
    return NextResponse.json({ error: (error as Error).message }, { status: 500 });
  }
}

export async function PUT(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  try {
    const body = await req.json();
    const existing = await getClient(id);
    if (!existing) {
      return NextResponse.json({ error: "Client not found" }, { status: 404 });
    }

    const updated: ClientConfig = {
      ...existing,
      clientName: body.clientName !== undefined ? body.clientName.trim() : existing.clientName,
      redirectUris: Array.isArray(body.redirectUris) ? body.redirectUris : existing.redirectUris,
      postLogoutRedirectUris: Array.isArray(body.postLogoutRedirectUris) ? body.postLogoutRedirectUris : existing.postLogoutRedirectUris,
      scopes: Array.isArray(body.scopes) ? body.scopes : existing.scopes,
      requireProofKey: body.requireProofKey !== undefined ? !!body.requireProofKey : existing.requireProofKey,
      accessTokenTimeToLiveMinutes: Number(body.accessTokenTimeToLiveMinutes) || existing.accessTokenTimeToLiveMinutes,
      refreshTokenTimeToLiveDays: Number(body.refreshTokenTimeToLiveDays) || existing.refreshTokenTimeToLiveDays,
      publicKeyPem: body.publicKeyPem?.trim() || existing.publicKeyPem,
    };

    await saveClient(updated);
    return NextResponse.json(updated);
  } catch (error) {
    return NextResponse.json({ error: (error as Error).message }, { status: 500 });
  }
}

export async function DELETE(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  try {
    const existing = await getClient(id);
    if (!existing) {
      return NextResponse.json({ error: "Client not found" }, { status: 404 });
    }
    await deleteClient(id);
    return NextResponse.json({ success: true, clientId: id });
  } catch (error) {
    return NextResponse.json({ error: (error as Error).message }, { status: 500 });
  }
}
