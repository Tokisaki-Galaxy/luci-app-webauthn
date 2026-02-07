import { http, HttpResponse } from 'msw'

// Mock responses matching the real backend (after middleware unwrapping).
// The middleware transforms { success, data } envelopes and field names.
const MOCK_RESPONSES = {
  'luci.webauthn': {
    health: {
      status: 'ok',
      version: '1.0.0',
      storage: { writable: true, path: '/etc/webauthn/credentials.json', count: 2 },
    },
    register_begin: {
      challengeId: 'mock-challenge-id-register',
      publicKey: {
        rp: { name: 'OpenWrt', id: 'localhost' },
        user: { id: 'cm9vdA', name: 'root', displayName: 'root' },
        challenge: 'dGVzdC1jaGFsbGVuZ2UtcmVnaXN0ZXI',
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        timeout: 60000,
        attestation: 'none',
        authenticatorSelection: {
          userVerification: 'preferred',
          residentKey: 'preferred',
        },
      },
    },
    register_finish: {
      credentialId: 'mock-credential-id',
      aaguid: '00000000-0000-0000-0000-000000000000',
      createdAt: '2025-01-15T10:30:00Z',
    },
    login_begin: {
      challengeId: 'mock-challenge-id-login',
      publicKey: {
        challenge: 'dGVzdC1jaGFsbGVuZ2UtbG9naW4',
        timeout: 60000,
        rpId: 'localhost',
        allowCredentials: [
          { type: 'public-key', id: 'bW9jay1jcmVkZW50aWFsLWlk' },
        ],
        userVerification: 'preferred',
      },
    },
    login_finish: { success: true, username: 'root', userVerified: true, counter: 1 },
    manage_list: {
      credentials: [
        {
          id: 'mock-credential-1',
          credentialId: 'mock-credential-1',
          username: 'root',
          deviceName: 'My Laptop Chrome',
          createdAt: '2025-01-15T10:30:00Z',
          lastUsedAt: '2025-06-01T08:00:00Z',
          backupEligible: false,
          userVerified: true,
        },
        {
          id: 'mock-credential-2',
          credentialId: 'mock-credential-2',
          username: 'root',
          deviceName: 'iPhone Safari',
          createdAt: '2025-03-20T14:00:00Z',
          lastUsedAt: null,
          backupEligible: false,
          userVerified: false,
        },
      ],
    },
    manage_delete: { credentialId: 'mock-credential-1', deleted: true },
    manage_update: {
      credentialId: 'mock-credential-1',
      oldName: 'My Laptop Chrome',
      newName: 'Updated Name',
    },
  },
}

export const handlers = [
  // Intercept ubus JSON-RPC calls (used by login page directly)
  http.post('/ubus', async ({ request }) => {
    const body = await request.json()
    if (body.method === 'call' && Array.isArray(body.params) && body.params.length >= 4) {
      const [, object, method] = body.params
      const response = MOCK_RESPONSES[object]?.[method]
      if (response) {
        return HttpResponse.json({
          jsonrpc: '2.0',
          id: body.id,
          result: [0, response],
        })
      }
    }
    return HttpResponse.json({
      jsonrpc: '2.0',
      id: body.id,
      error: { code: -32000, message: 'Object not found' },
    })
  }),
]
