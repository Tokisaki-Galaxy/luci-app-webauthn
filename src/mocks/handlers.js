import { http, HttpResponse } from 'msw'

// Mock responses for each ubus method
const MOCK_RESPONSES = {
  'luci.webauthn': {
    health: { status: 'ok', version: '1.0.0' },
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
    register_finish: { success: true, credentialId: 'mock-credential-id' },
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
    login_finish: { success: true },
    manage_list: {
      credentials: [
        {
          id: 'mock-credential-1',
          deviceName: 'My Laptop Chrome',
          createdAt: '2025-01-15T10:30:00Z',
          lastUsedAt: '2025-06-01T08:00:00Z',
          userVerified: true,
        },
        {
          id: 'mock-credential-2',
          deviceName: 'iPhone Safari',
          createdAt: '2025-03-20T14:00:00Z',
          lastUsedAt: null,
          userVerified: false,
        },
      ],
    },
    manage_delete: { success: true },
    manage_update: { success: true },
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
