import { createHash } from "crypto";

function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

const SPRING_AUTH_SERVER_URL = process.env.SPRING_AUTH_SERVER_URL || "http://localhost:9000";
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || "secret-admin-key";
const FETCH_TIMEOUT_MS = 5000;

export interface AppUser {
  id: string;
  email: string;
  is_fraud: boolean;
}

export interface PagedUsers {
  users: AppUser[];
  total: number;
  page: number;
  totalPages: number;
}

async function fetchWithTimeout(url: string, options: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    return response;
  } finally {
    clearTimeout(id);
  }
}

export async function listUsers(page: number = 1, limit: number = 10): Promise<PagedUsers> {
  try {
    const res = await fetchWithTimeout(`${SPRING_AUTH_SERVER_URL}/api/admin/users?page=${page}&limit=${limit}`, {
      headers: { "X-Admin-Api-Key": ADMIN_API_KEY },
      cache: "no-store",
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.error("Failed to fetch users", err);
    return { users: [], total: 0, page: 1, totalPages: 1 };
  }
}

export async function flagUserFraud(email: string): Promise<void> {
  const res = await fetchWithTimeout(`${SPRING_AUTH_SERVER_URL}/api/admin/users/${encodeURIComponent(email)}/fraud`, {
    method: "POST",
    headers: { "X-Admin-Api-Key": ADMIN_API_KEY },
  });
  if (!res.ok) {
    throw new Error(`Failed to flag user: HTTP ${res.status}`);
  }
}

export async function unflagUserFraud(email: string): Promise<void> {
  const res = await fetchWithTimeout(`${SPRING_AUTH_SERVER_URL}/api/admin/users/${encodeURIComponent(email)}/unfraud`, {
    method: "POST",
    headers: { "X-Admin-Api-Key": ADMIN_API_KEY },
  });
  if (!res.ok) {
    throw new Error(`Failed to unflag user: HTTP ${res.status}`);
  }
}

export interface CreateUserInput {
  email: string;
  password?: string;
}

export async function createUser(data: CreateUserInput): Promise<void> {
  const payload: CreateUserInput = { ...data };
  if (payload.password) {
    payload.password = sha256(payload.password);
  }
  const res = await fetchWithTimeout(`${SPRING_AUTH_SERVER_URL}/api/admin/users`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Admin-Api-Key": ADMIN_API_KEY,
    },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`Failed to create user: HTTP ${res.status}`);
  }
}

export async function editUser(oldEmail: string, data: { email?: string; password?: string }): Promise<void> {
  const payload = { ...data };
  if (payload.password && payload.password.length > 0) {
    payload.password = sha256(payload.password);
  }
  const res = await fetchWithTimeout(`${SPRING_AUTH_SERVER_URL}/api/admin/users/${encodeURIComponent(oldEmail)}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "X-Admin-Api-Key": ADMIN_API_KEY,
    },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`Failed to edit user: HTTP ${res.status}`);
  }
}
