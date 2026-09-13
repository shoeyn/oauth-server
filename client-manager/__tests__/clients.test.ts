import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { listClients, getClient, saveClient, deleteClient } from '../lib/clients';

describe('clients api', () => {
  const originalFetch = global.fetch;
  const mockFetch = vi.fn();

  beforeEach(() => {
    global.fetch = mockFetch;
    vi.useFakeTimers();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  describe('listClients', () => {
    it('should list clients successfully', async () => {
      const mockClients = [{ clientId: 'test-client' }];
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockClients
      } as Response);

      const clients = listClients();
      vi.runAllTimers();
      
      const res = await clients;
      expect(res).toEqual(mockClients);
      expect(mockFetch).toHaveBeenCalledWith(expect.stringContaining('/api/admin/clients'), expect.any(Object));
    });

    it('should return empty array on non-ok response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500
      } as Response);

      const clients = listClients();
      vi.runAllTimers();
      
      const res = await clients;
      expect(res).toEqual([]);
    });

    it('should return empty array on fetch error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const clients = listClients();
      vi.runAllTimers();
      
      const res = await clients;
      expect(res).toEqual([]);
    });
  });

  describe('getClient', () => {
    it('should return a client successfully', async () => {
      const mockClient = { clientId: 'test-client' };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockClient
      } as Response);

      const client = getClient('test-client');
      vi.runAllTimers();
      
      const res = await client;
      expect(res).toEqual(mockClient);
    });

    it('should return null on 404', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404
      } as Response);

      const client = getClient('test-client');
      vi.runAllTimers();
      
      const res = await client;
      expect(res).toBeNull();
    });

    it('should return null on non-ok response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500
      } as Response);

      const client = getClient('test-client');
      vi.runAllTimers();
      
      const res = await client;
      expect(res).toBeNull();
    });

    it('should return null on fetch error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const client = getClient('test-client');
      vi.runAllTimers();
      
      const res = await client;
      expect(res).toBeNull();
    });
  });

  describe('saveClient', () => {
    it('should save a client successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true
      } as Response);

      const save = saveClient({ clientId: 'test-client' } as any);
      vi.runAllTimers();
      
      await expect(save).resolves.toBeUndefined();
    });

    it('should throw error on non-ok response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        text: async () => 'Bad Request'
      } as Response);

      const save = saveClient({ clientId: 'test-client' } as any);
      vi.runAllTimers();
      
      await expect(save).rejects.toThrow('Failed to save client: HTTP 400 - Bad Request');
    });
  });

  describe('deleteClient', () => {
    it('should delete a client successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true
      } as Response);

      const del = deleteClient('test-client');
      vi.runAllTimers();
      
      await expect(del).resolves.toBeUndefined();
    });

    it('should resolve if client is not found (404)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404
      } as Response);

      const del = deleteClient('test-client');
      vi.runAllTimers();
      
      await expect(del).resolves.toBeUndefined();
    });

    it('should throw error on non-ok response other than 404', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: async () => 'Server Error'
      } as Response);

      const del = deleteClient('test-client');
      vi.runAllTimers();
      
      await expect(del).rejects.toThrow('Failed to delete client: HTTP 500 - Server Error');
    });
  });
});
