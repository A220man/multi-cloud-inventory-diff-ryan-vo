/**
 * Boundary regression test for the typed demo-login client.
 *
 * Verifies that loginDemo derives AuthState from the REAL backend
 * /api/auth/demo-token response envelope (access_token-based OAuth2
 * style response), not the mock shape used by component tests. The
 * transport (global fetch) is mocked so no network is required.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { loginDemo } from '../services/api';

function jsonResponse(body: unknown, ok = true, status = 200, statusText = 'OK') {
  return {
    ok,
    status,
    statusText,
    json: async () => body,
    text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
  } as unknown as Response;
}

describe('loginDemo typed client (transport boundary)', () => {
  afterEach(() => vi.restoreAllMocks());

  it('maps backend access_token envelope to AuthState and forwards role/username', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse({
        access_token: 'local-demo-token',
        token_type: 'Bearer',
        role: 'viewer',
        username: 'alice',
        expires_in: 28800,
      })
    );

    const auth = await loginDemo({ role: 'viewer', username: 'alice' });

    // Envelope mapping contract (fixes previously-broken AuthState)
    expect(auth.token).toBe('local-demo-token');
    expect(auth.isAuthenticated).toBe(true);
    expect(auth.role).toBe('viewer');
    expect(auth.username).toBe('alice');

    // Payload is actually forwarded on the wire
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [input, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(input).toMatch(/\/api\/auth\/demo-token$/);
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({
      role: 'viewer',
      username: 'alice',
    });
  });

  it('propagates backend errors without partial session state', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse('Demo token endpoint disabled. Production requires Keycloak OIDC.', false, 403, 'Forbidden')
    );

    await expect(loginDemo({ role: 'admin', username: 'demo-user' })).rejects.toThrow(
      /Demo token endpoint disabled/
    );
  });
});