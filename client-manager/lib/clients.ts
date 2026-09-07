import { ClientConfig } from "./types";

const SPRING_AUTH_SERVER_URL = process.env.SPRING_AUTH_SERVER_URL || "http://localhost:9000";
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || "secret-admin-key";

export async function listClients(): Promise<ClientConfig[]> {
  try {
    const res = await fetch(`${SPRING_AUTH_SERVER_URL}/api/admin/clients`, {
      headers: {
        "X-Admin-Api-Key": ADMIN_API_KEY,
      },
      cache: "no-store",
    });

    if (!res.ok) {
      throw new Error(`Spring Admin API returned HTTP ${res.status}`);
    }

    const data = await res.json();
    return data as ClientConfig[];
  } catch (err) {
    console.error("[Client Admin] Failed to fetch clients from Spring:", err);
    return [];
  }
}

export async function getClient(clientId: string): Promise<ClientConfig | null> {
  try {
    const res = await fetch(`${SPRING_AUTH_SERVER_URL}/api/admin/clients/${encodeURIComponent(clientId)}`, {
      headers: {
        "X-Admin-Api-Key": ADMIN_API_KEY,
      },
      cache: "no-store",
    });

    if (res.status === 404) {
      return null;
    }

    if (!res.ok) {
      throw new Error(`Spring Admin API returned HTTP ${res.status}`);
    }

    const data = await res.json();
    return data as ClientConfig;
  } catch (err) {
    console.error(`[Client Admin] Failed to get client ${clientId}:`, err);
    return null;
  }
}

export async function saveClient(client: ClientConfig): Promise<void> {
  const res = await fetch(`${SPRING_AUTH_SERVER_URL}/api/admin/clients`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Admin-Api-Key": ADMIN_API_KEY,
    },
    body: JSON.stringify(client),
  });

  if (!res.ok) {
    const errorBody = await res.text();
    throw new Error(`Failed to save client: HTTP ${res.status} - ${errorBody}`);
  }
}

export async function deleteClient(clientId: string): Promise<void> {
  const res = await fetch(`${SPRING_AUTH_SERVER_URL}/api/admin/clients/${encodeURIComponent(clientId)}`, {
    method: "DELETE",
    headers: {
      "X-Admin-Api-Key": ADMIN_API_KEY,
    },
  });

  if (!res.ok && res.status !== 404) {
    const errorBody = await res.text();
    throw new Error(`Failed to delete client: HTTP ${res.status} - ${errorBody}`);
  }
}
