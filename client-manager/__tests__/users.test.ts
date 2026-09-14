import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { listUsers, flagUserFraud, unflagUserFraud, createUser, editUser } from '../lib/users';

const originalFetch = global.fetch;

describe('users api', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  describe('listUsers', () => {
    it('should return users', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => [{ id: '1', username: 'alice' }],
      });
      const users = await listUsers();
      expect(users).toEqual([{ id: '1', username: 'alice' }]);
    });

    it('should handle fetch error', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));
      const users = await listUsers();
      expect(users).toEqual({ users: [], total: 0, page: 1, totalPages: 1 });
    });

    it('should handle non-ok response', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Server Error')
      });
      const users = await listUsers();
      expect(users).toEqual({ users: [], total: 0, page: 1, totalPages: 1 });
    });
  });

  describe('flagUserFraud', () => {
    it('should resolve on success', async () => {
      global.fetch = vi.fn().mockResolvedValue({ ok: true });
      await expect(flagUserFraud('alice')).resolves.toBeUndefined();
    });

    it('should throw on error', async () => {
      global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 404 });
      await expect(flagUserFraud('alice')).rejects.toThrow('Failed to flag user: HTTP 404');
    });
  });

  describe('unflagUserFraud', () => {
    it('should resolve on success', async () => {
      global.fetch = vi.fn().mockResolvedValue({ ok: true });
      await expect(unflagUserFraud('alice')).resolves.toBeUndefined();
    });

    it('should throw on error', async () => {
      global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 404 });
      await expect(unflagUserFraud('alice')).rejects.toThrow('Failed to unflag user: HTTP 404');
    });
  });

  describe('createUser', () => {
    it('should resolve on success and hash password', async () => {
      const fetchSpy = vi.fn().mockResolvedValue({ ok: true });
      global.fetch = fetchSpy;
      await expect(createUser({ username: 'bob', password: 'password123' })).resolves.toBeUndefined();
      
      const calledWithUrl = fetchSpy.mock.calls[0][0];
      const calledWithOptions = fetchSpy.mock.calls[0][1];
      const body = JSON.parse(calledWithOptions.body);
      
      expect(body.password).not.toBe('password123');
      // sha256 of 'password123' is ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
      expect(body.password).toBe('ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f');
    });

    it('should resolve if no password provided', async () => {
      global.fetch = vi.fn().mockResolvedValue({ ok: true });
      await expect(createUser({ username: 'bob' })).resolves.toBeUndefined();
    });

    it('should throw on error', async () => {
      global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500 });
      await expect(createUser({ username: 'bob' })).rejects.toThrow('Failed to create user: HTTP 500');
    });
  });

  describe('editUser', () => {
    it('should resolve on success and hash password if provided', async () => {
      const fetchSpy = vi.fn().mockResolvedValue({ ok: true });
      global.fetch = fetchSpy;
      await expect(editUser('bob', { email: 'bob@new.com', password: 'newpassword' })).resolves.toBeUndefined();
      
      const calledWithOptions = fetchSpy.mock.calls[0][1];
      const body = JSON.parse(calledWithOptions.body);
      expect(body.password).not.toBe('newpassword');
      // We know it gets hashed, just checking it's changed.
      expect(body.password).toBeTruthy();
    });

    it('should resolve if no password provided or empty', async () => {
      const fetchSpy = vi.fn().mockResolvedValue({ ok: true });
      global.fetch = fetchSpy;
      await expect(editUser('bob', { email: 'bob@new.com', password: '' })).resolves.toBeUndefined();
      
      const calledWithOptions = fetchSpy.mock.calls[0][1];
      const body = JSON.parse(calledWithOptions.body);
      expect(body.password).toBe(''); // unchanged empty string
    });

    it('should throw on error', async () => {
      global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500 });
      await expect(editUser('bob', {})).rejects.toThrow('Failed to edit user: HTTP 500');
    });
  });
});
