import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@/lib/clients', () => ({
  getClient: vi.fn(),
  saveClient: vi.fn(),
  deleteClient: vi.fn(),
}));

import { GET, PUT, DELETE } from '../app/api/clients/[id]/route';
import { getClient, saveClient, deleteClient } from '@/lib/clients';
import type { ClientConfig } from '@/lib/types';

const mockGetClient = vi.mocked(getClient);
const mockSaveClient = vi.mocked(saveClient);
const mockDeleteClient = vi.mocked(deleteClient);

const existingClient: ClientConfig = {
  clientId: 'demo-client',
  clientName: 'Demo Client',
  clientAuthenticationMethods: ['private_key_jwt'],
  authorizationGrantTypes: ['authorization_code', 'refresh_token'],
  redirectUris: ['https://demo/cb'],
  postLogoutRedirectUris: ['https://demo/logout'],
  scopes: ['openid', 'profile'],
  requireProofKey: true,
  requireAuthorizationConsent: false,
  requirePushedAuthorizationRequests: true,
  accessTokenTimeToLiveMinutes: 15,
  refreshTokenTimeToLiveDays: 30,
  publicKeyPem: '-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----',
};

// The Next.js App Router passes params as a Promise.
function ctx(id: string) {
  return { params: Promise.resolve({ id }) };
}

function putRequest(body: unknown): Request {
  return new Request('http://localhost:3001/api/clients/demo-client', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

const emptyRequest = () => new Request('http://localhost:3001/api/clients/demo-client');

describe('GET /api/clients/[id]', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns 404 when the client does not exist', async () => {
    mockGetClient.mockResolvedValueOnce(null);

    const res = await GET(emptyRequest(), ctx('missing'));

    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: 'Client not found' });
    expect(mockGetClient).toHaveBeenCalledWith('missing');
  });

  it('returns 200 with the client when found', async () => {
    mockGetClient.mockResolvedValueOnce(existingClient);

    const res = await GET(emptyRequest(), ctx('demo-client'));

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(existingClient);
  });

  it('returns 500 when lookup throws', async () => {
    mockGetClient.mockRejectedValueOnce(new Error('lookup failed'));

    const res = await GET(emptyRequest(), ctx('demo-client'));

    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: 'lookup failed' });
  });
});

describe('PUT /api/clients/[id]', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns 404 when the client does not exist', async () => {
    mockGetClient.mockResolvedValueOnce(null);

    const res = await PUT(putRequest({ clientName: 'x' }), ctx('missing'));

    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: 'Client not found' });
    expect(mockSaveClient).not.toHaveBeenCalled();
  });

  it('merges supplied fields over the existing client and returns 200', async () => {
    mockGetClient.mockResolvedValueOnce(existingClient);
    mockSaveClient.mockResolvedValueOnce(undefined as never);

    const res = await PUT(
      putRequest({
        clientName: '  New Name  ',
        redirectUris: ['https://new/cb'],
        postLogoutRedirectUris: ['https://new/logout'],
        scopes: ['openid'],
        requireProofKey: false,
        requirePushedAuthorizationRequests: false,
        accessTokenTimeToLiveMinutes: 5,
        refreshTokenTimeToLiveDays: 60,
        publicKeyPem: '  -----BEGIN PUBLIC KEY-----\nBBB\n-----END PUBLIC KEY-----  ',
      }),
      ctx('demo-client')
    );

    expect(res.status).toBe(200);
    const updated = await res.json();

    expect(updated.clientId).toBe('demo-client');
    expect(updated.clientName).toBe('New Name');
    expect(updated.redirectUris).toEqual(['https://new/cb']);
    expect(updated.scopes).toEqual(['openid']);
    expect(updated.requireProofKey).toBe(false);
    expect(updated.requirePushedAuthorizationRequests).toBe(false);
    expect(updated.accessTokenTimeToLiveMinutes).toBe(5);
    expect(updated.refreshTokenTimeToLiveDays).toBe(60);
    expect(updated.publicKeyPem).toBe('-----BEGIN PUBLIC KEY-----\nBBB\n-----END PUBLIC KEY-----');
    // postLogoutRedirectUris supplied as an array is applied over the existing value.
    expect(updated.postLogoutRedirectUris).toEqual(['https://new/logout']);
    // Fields not present in the body are preserved from the existing client.
    expect(updated.authorizationGrantTypes).toEqual(existingClient.authorizationGrantTypes);
    expect(mockSaveClient).toHaveBeenCalledWith(updated);
  });

  it('preserves existing values when body omits fields / provides invalid TTLs', async () => {
    mockGetClient.mockResolvedValueOnce(existingClient);
    mockSaveClient.mockResolvedValueOnce(undefined as never);

    const res = await PUT(
      putRequest({
        accessTokenTimeToLiveMinutes: 0,
        refreshTokenTimeToLiveDays: 'bad',
        publicKeyPem: '   ',
      }),
      ctx('demo-client')
    );

    expect(res.status).toBe(200);
    const updated = await res.json();

    expect(updated.clientName).toBe(existingClient.clientName);
    expect(updated.redirectUris).toEqual(existingClient.redirectUris);
    expect(updated.postLogoutRedirectUris).toEqual(existingClient.postLogoutRedirectUris);
    expect(updated.scopes).toEqual(existingClient.scopes);
    expect(updated.requireProofKey).toBe(existingClient.requireProofKey);
    expect(updated.requirePushedAuthorizationRequests).toBe(existingClient.requirePushedAuthorizationRequests);
    expect(updated.accessTokenTimeToLiveMinutes).toBe(existingClient.accessTokenTimeToLiveMinutes);
    expect(updated.refreshTokenTimeToLiveDays).toBe(existingClient.refreshTokenTimeToLiveDays);
    // Whitespace-only PEM falls back to the existing key.
    expect(updated.publicKeyPem).toBe(existingClient.publicKeyPem);
  });

  it('returns 500 when the update throws', async () => {
    mockGetClient.mockResolvedValueOnce(existingClient);
    mockSaveClient.mockRejectedValueOnce(new Error('save failed'));

    const res = await PUT(putRequest({ clientName: 'x' }), ctx('demo-client'));

    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: 'save failed' });
  });
});

describe('DELETE /api/clients/[id]', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns 404 when the client does not exist', async () => {
    mockGetClient.mockResolvedValueOnce(null);

    const res = await DELETE(emptyRequest(), ctx('missing'));

    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: 'Client not found' });
    expect(mockDeleteClient).not.toHaveBeenCalled();
  });

  it('deletes an existing client and returns 200', async () => {
    mockGetClient.mockResolvedValueOnce(existingClient);
    mockDeleteClient.mockResolvedValueOnce(undefined as never);

    const res = await DELETE(emptyRequest(), ctx('demo-client'));

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ success: true, clientId: 'demo-client' });
    expect(mockDeleteClient).toHaveBeenCalledWith('demo-client');
  });

  it('returns 500 when deletion throws', async () => {
    mockGetClient.mockResolvedValueOnce(existingClient);
    mockDeleteClient.mockRejectedValueOnce(new Error('delete failed'));

    const res = await DELETE(emptyRequest(), ctx('demo-client'));

    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: 'delete failed' });
  });
});
