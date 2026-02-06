import { http, HttpResponse } from 'msw'

const RPC_BASE = '/cgi-bin/luci/rpc/webauthn'

export const handlers = [
  http.get(`${RPC_BASE}/health`, () => {
    return HttpResponse.json({ status: 'ok', version: '1.0.0' })
  }),

  http.post(`${RPC_BASE}/register_begin`, () => {
    return HttpResponse.json({
      challengeId: 'mock-challenge-id-register',
      publicKey: {
        rp: { name: 'OpenWrt', id: 'localhost' },
        user: {
          id: 'cm9vdA',
          name: 'root',
          displayName: 'root',
        },
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
    })
  }),

  http.post(`${RPC_BASE}/register_finish`, () => {
    return HttpResponse.json({ success: true, credentialId: 'mock-credential-id' })
  }),

  http.post(`${RPC_BASE}/login_begin`, () => {
    return HttpResponse.json({
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
    })
  }),

  http.post(`${RPC_BASE}/login_finish`, () => {
    return HttpResponse.json({ success: true })
  }),

  http.get(`${RPC_BASE}/manage_list`, () => {
    return HttpResponse.json({
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
    })
  }),

  http.post(`${RPC_BASE}/manage_delete`, () => {
    return HttpResponse.json({ success: true })
  }),

  http.post(`${RPC_BASE}/manage_update`, () => {
    return HttpResponse.json({ success: true })
  }),
]
