import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the data-access layer so the route handlers are tested in isolation.
vi.mock('@/lib/clients', () => ({
  listClients: vi.fn(),
  saveClient: vi.fn(),
}));

import { GET, POST } from '../app/api/clients/route';
import { listClients, saveClient } from '@/lib/clients';

const mockListClients = vi.mocked(listClients);
const mockSaveClient = vi.mocked(saveClient);

const VALID_PEM = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...\n-----END PUBLIC KEY-----';

function postRequest(body: unknown): Request {
  return new Request('http://localhost:3001/api/clients', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

describe('GET /api/clients', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns the list of clients with 200', async () => {
    const clients = [{ clientId: 'demo-client' }, { clientId: 'other' }];
    mockListClients.mockResolvedValueOnce(clients as never);

    const res = await GET();

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(clients);
    expect(mockListClients).toHaveBeenCalledOnce();
  });

  it('returns 500 with the error message when listing throws', async () => {
    mockListClients.mockRejectedValueOnce(new Error('spring down'));

    const res = await GET();

    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: 'spring down' });
  });
});

describe('POST /api/clients', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns 400 when clientId is missing', async () => {
    const res = await POST(postRequest({ publicKeyPem: VALID_PEM }));

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: 'clientId is required' });
    expect(mockSaveClient).not.toHaveBeenCalled();
  });

  it('returns 400 when clientId is not a string', async () => {
    const res = await POST(postRequest({ clientId: 123, publicKeyPem: VALID_PEM }));

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: 'clientId is required' });
    expect(mockSaveClient).not.toHaveBeenCalled();
  });

  it('returns 400 when publicKeyPem is missing', async () => {
    const res = await POST(postRequest({ clientId: 'demo' }));

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: 'A valid RSA public key in PEM format is required',
    });
    expect(mockSaveClient).not.toHaveBeenCalled();
  });

  it('returns 400 when publicKeyPem does not contain a PEM header', async () => {
    const res = await POST(postRequest({ clientId: 'demo', publicKeyPem: 'not-a-key' }));

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: 'A valid RSA public key in PEM format is required',
    });
    expect(mockSaveClient).not.toHaveBeenCalled();
  });

  it('creates a client with 201 applying secure defaults when optional fields are omitted', async () => {
    mockSaveClient.mockResolvedValueOnce(undefined as never);

    const res = await POST(postRequest({ clientId: '  demo-client  ', publicKeyPem: VALID_PEM }));

    expect(res.status).toBe(201);
    const created = await res.json();

    // clientId/clientName trimmed; clientName defaults to clientId.
    expect(created.clientId).toBe('demo-client');
    expect(created.clientName).toBe('demo-client');
    // Enforced private_key_jwt-only client authentication.
    expect(created.clientAuthenticationMethods).toEqual(['private_key_jwt']);
    // Default grant types applied.
    expect(created.authorizationGrantTypes).toEqual([
      'authorization_code',
      'refresh_token',
      'client_credentials',
    ]);
    expect(created.redirectUris).toEqual([]);
    expect(created.postLogoutRedirectUris).toEqual([]);
    expect(created.scopes).toEqual(['openid', 'profile', 'email']);
    // Security-critical defaults must default to true when unspecified.
    expect(created.requireProofKey).toBe(true);
    expect(created.requireAuthorizationConsent).toBe(false);
    expect(created.requirePushedAuthorizationRequests).toBe(true);
    expect(created.accessTokenTimeToLiveMinutes).toBe(15);
    expect(created.refreshTokenTimeToLiveDays).toBe(30);
    expect(created.publicKeyPem).toBe(VALID_PEM);

    expect(mockSaveClient).toHaveBeenCalledOnce();
    expect(mockSaveClient).toHaveBeenCalledWith(created);
  });

  it('honours supplied values including disabling PKCE/PAR and custom collections', async () => {
    mockSaveClient.mockResolvedValueOnce(undefined as never);

    const res = await POST(
      postRequest({
        clientId: 'custom',
        clientName: '  Custom App  ',
        authorizationGrantTypes: ['authorization_code'],
        redirectUris: ['  https://app/cb  ', '', '  '],
        postLogoutRedirectUris: ['  https://app/logout  '],
        scopes: ['openid', 'user.read'],
        requireProofKey: false,
        requirePushedAuthorizationRequests: false,
        accessTokenTimeToLiveMinutes: 5,
        refreshTokenTimeToLiveDays: 90,
        publicKeyPem: `  ${VALID_PEM}  `,
      })
    );

    expect(res.status).toBe(201);
    const created = await res.json();

    expect(created.clientName).toBe('Custom App');
    expect(created.authorizationGrantTypes).toEqual(['authorization_code']);
    // Empty/whitespace redirect URIs are trimmed and filtered out.
    expect(created.redirectUris).toEqual(['https://app/cb']);
    expect(created.postLogoutRedirectUris).toEqual(['https://app/logout']);
    expect(created.scopes).toEqual(['openid', 'user.read']);
    expect(created.requireProofKey).toBe(false);
    expect(created.requirePushedAuthorizationRequests).toBe(false);
    expect(created.accessTokenTimeToLiveMinutes).toBe(5);
    expect(created.refreshTokenTimeToLiveDays).toBe(90);
    expect(created.publicKeyPem).toBe(VALID_PEM);
  });

  it('falls back to defaults when numeric TTLs are zero/invalid and scopes is empty', async () => {
    mockSaveClient.mockResolvedValueOnce(undefined as never);

    const res = await POST(
      postRequest({
        clientId: 'edge',
        publicKeyPem: VALID_PEM,
        scopes: [],
        accessTokenTimeToLiveMinutes: 0,
        refreshTokenTimeToLiveDays: 'nope',
      })
    );

    expect(res.status).toBe(201);
    const created = await res.json();
    expect(created.scopes).toEqual(['openid', 'profile', 'email']);
    expect(created.accessTokenTimeToLiveMinutes).toBe(15);
    expect(created.refreshTokenTimeToLiveDays).toBe(30);
  });

  it('returns 500 when saveClient throws', async () => {
    mockSaveClient.mockRejectedValueOnce(new Error('persist failed'));

    const res = await POST(postRequest({ clientId: 'demo', publicKeyPem: VALID_PEM }));

    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: 'persist failed' });
  });
});
