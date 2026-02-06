# Frontend Requirements: LuCI App for WebAuthn

**Version**: 1.0
**Target Framework**: OpenWrt LuCI (Client-side JS + Server-side ucode)
**Backend Dependency**: `webauthn-helper` (Rust CLI v1.0)
**Protocol**: JSON-RPC over HTTP

## 1. Architecture Overview

Since the browser cannot execute the Rust CLI directly, the frontend consists of two layers:
1.  **Client Layer (Browser JS)**: Handles `navigator.credentials` API, Base64URL encoding/decoding, and UI rendering.
2.  **Middleware Layer (ucode)**: Exposes HTTP endpoints (LuCI RPC), executes the `webauthn-helper` CLI, handles `stdin` passing, and forwards JSON responses.

```mermaid
Browser (JS)  <-->  HTTP (JSON)  <-->  LuCI (ucode)  <-->  Rust CLI (webauthn-helper)
```

## 2. API / Middleware Contract (ucode Layer)

The ucode scripts typically reside in `/usr/share/ucode/luci/controller/webauthn.uc` or similar, mapping HTTP requests to CLI commands.

**Global Requirement for Middleware**:
*   Must pass `HTTP_ORIGIN` or `HTTP_HOST` headers to the CLI's `--origin` flag.
*   Must handle `stdin` piping for `*-finish` commands.
*   Must return `500` status if the CLI exits with non-zero, but still pass the JSON error body.

### 2.1 Endpoints

| Endpoint URL | Method | Backend Command | Input (JSON Body) |
|---|---|---|---|
| `/cgi-bin/luci/rpc/webauthn/register_begin` | POST | `register-begin` | `{ username, userVerification }` |
| `/cgi-bin/luci/rpc/webauthn/register_finish` | POST | `register-finish` | `{ challengeId, deviceName, ...clientJson }` |
| `/cgi-bin/luci/rpc/webauthn/login_begin` | POST | `login-begin` | `{ username }` |
| `/cgi-bin/luci/rpc/webauthn/login_finish` | POST | `login-finish` | `{ challengeId, ...clientJson }` |
| `/cgi-bin/luci/rpc/webauthn/manage_list` | GET | `credential-manage list` | - |
| `/cgi-bin/luci/rpc/webauthn/manage_delete` | POST | `credential-manage delete` | `{ id }` |
| `/cgi-bin/luci/rpc/webauthn/manage_update` | POST | `credential-manage update` | `{ id, name }` |
| `/cgi-bin/luci/rpc/webauthn/health` | GET | `health-check` | - |

## 3. Client-Side Implementation Details (JavaScript)

### 3.1 Critical Utility Functions
WebAuthn API requires `ArrayBuffer`, but backend transmits `Base64URL String`. Front-end **MUST** implement robust converters.

```javascript
const utils = {
    // Base64URL string -> ArrayBuffer
    decode: (str) => {
        const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
        const arr = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
        return arr.buffer;
    },
    // ArrayBuffer -> Base64URL string
    encode: (buf) => {
        const bin = String.fromCharCode(...new Uint8Array(buf));
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
};
```

### 3.2 Registration Flow (Logic)
**Trigger**: Button "Register New Passkey" in Settings.

1.  **Request Options**:
    *   Call `rpc/webauthn/register_begin`.
    *   Receive JSON (Schema A from Backend Doc).
    *   **Transformation**:
        *   `data.publicKey.challenge` -> `utils.decode()`
        *   `data.publicKey.user.id` -> `utils.decode()`
2.  **Browser Interaction**:
    *   Call `navigator.credentials.create({ publicKey: opts })`.
3.  **Process Response**:
    *   **Transformation** (Prepare for Schema B Input):
        *   `cred.id` -> No change (it's base64url string in modern browsers, or encode `cred.rawId`).
        *   `cred.response.clientDataJSON` -> `utils.encode()`
        *   `cred.response.attestationObject` -> `utils.encode()`
4.  **Finalize**:
    *   Call `rpc/webauthn/register_finish` with payload:
        ```json
        {
            "challengeId": "<from_step_1>",
            "deviceName": "<user_input_or_user_agent>",
            "id": "...",
            "type": "public-key",
            "response": { "clientDataJSON": "...", "attestationObject": "..." }
        }
        ```
5.  **UI Update**: Show success message, refresh management table.

### 3.3 Login Flow (Logic)
**Trigger**: Button "Login with Passkey" on Login Page.

1.  **Request Challenge**:
    *   Call `rpc/webauthn/login_begin`.
    *   Receive JSON (Schema C).
    *   **Transformation**:
        *   `data.publicKey.challenge` -> `utils.decode()`
        *   `data.publicKey.allowCredentials[i].id` -> `utils.decode()`
2.  **Browser Interaction**:
    *   Call `navigator.credentials.get({ publicKey: opts })`.
3.  **Process Response**:
    *   **Transformation** (Prepare for Schema D Input):
        *   `cred.response.authenticatorData` -> `utils.encode()`
        *   `cred.response.signature` -> `utils.encode()`
        *   `cred.response.clientDataJSON` -> `utils.encode()`
        *   `cred.response.userHandle` -> `utils.encode()` (if present)
4.  **Finalize**:
    *   Call `rpc/webauthn/login_finish`.
5.  **Session Handling**:
    *   If backend returns `{ success: true }`, the ucode script MUST generate a standard LuCI session token (sysauth) and return it, or set the cookie header.
    *   Redirect to `/cgi-bin/luci/`.

## 4. UI Requirements (Screens)

### 4.1 Login Screen (`/www/luci-static/resources/view/system/login.js`)

*   **Initialization**:
    *   On load, call `rpc/webauthn/health`.
    *   **IF** `success: false` OR `status != "ok"`: **Hide** the "Login with Passkey" button.
    *   **ELSE**: Show button.
*   **Layout**:
    *   Add a visual separator below the standard Password form.
    *   Add a prominent "🔑 Passkey" button.
*   **Feedback**:
    *   Show a spinner while waiting for the browser/backend.
    *   Show user-friendly error messages (e.g., "Device not found" instead of "Error 404").

### 4.2 Management Screen (`admin/system/admin/webauthn`)

**Table Columns (Data Source: Schema E)**:
| Column Header | Data Field | Rendering Logic |
|---|---|---|
| Device Name | `deviceName` | Editable text field (calls `update` API on blur/enter) |
| Registered | `createdAt` | Format as `YYYY-MM-DD` |
| Last Used | `lastUsedAt` | Format as "2 days ago" or date |
| Verified | `userVerified` | Icon (Green Check if true) |
| Actions | - | [Delete] Button (Red) |

**Functionality**:
1.  **Load**: `rpc/webauthn/manage_list`.
2.  **Rename**: When `deviceName` is edited, call `rpc/webauthn/manage_update`.
    *   Payload: `{ id: <credentialId>, name: <new_value> }`
3.  **Delete**: Confirmation dialog -> `rpc/webauthn/manage_delete`.
4.  **Add**: Triggers the **Registration Flow** (See 3.2).

## 5. Error Handling & Edge Cases

The Frontend must map backend error codes to localized strings.

| Backend Error Code | User Message (EN) |
|---|---|
| `CHALLENGE_EXPIRED` | "Time limit exceeded. Please try again." |
| `INVALID_ORIGIN` | "Security Check Failed: Domain mismatch." |
| `CLONE_WARNING` | "Security Alert: This key may have been cloned!" |
| `USER_CANCELLED` (Browser) | "Operation cancelled." |
| `NOT_ALLOWED_ERROR` (Browser) | "No matching passkey found on this device." |

## 6. Security Constraints (Frontend)

1.  **HTTPS Requirement**:
    *   WebAuthn API **will fail** in the browser if the page is not served over HTTPS (or `localhost`).
    *   The Frontend script should detect `window.isSecureContext`.
    *   If `false`, display a warning: *"Passkeys require HTTPS. Please configure SSL/TLS on this router."* and disable the buttons.

2.  **XSS Protection**:
    *   Do not use `innerHTML` when rendering user-provided `deviceName`. Use `innerText` or LuCI's DOM builder to prevent injection.

## 7. Development Roadmap (Frontend)

1.  **Mocking (Day 1)**:
    *   Create a simple HTTP server (Node/Python) that serves static JSONs matching the Backend Schema A-G.
    *   Develop the JS `utils.encode/decode` logic against these mocks.
2.  **UI Implementation (Day 2)**:
    *   Implement the Management Table using LuCI's `form.GridSection` or `view.extend`.
3.  **Integration (Day 3)**:
    *   Replace Mocks with actual calls to LuCI RPC.
    *   Test with the actual Rust binary.

---

**Appendix: Sample Data for Mocking**
(Use the JSON Schemas A-G from the Backend Requirements Document V2.0)
