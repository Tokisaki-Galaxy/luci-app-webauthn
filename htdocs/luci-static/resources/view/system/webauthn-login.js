/* WebAuthn Login Page Enhancement
 * Loaded on the LuCI login page via the auth.d plugin HTML injection.
 * Handles the WebAuthn authentication ceremony (navigator.credentials.get).
 *
 * Copyright 2025 Tokisaki-Galaxy
 * Licensed under the Apache License 2.0
 */

(function() {
	'use strict';

	var RPC_BASE = '/cgi-bin/luci/rpc/webauthn/';

	var utils = {
		decode: function(str) {
			var bin = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
			var arr = new Uint8Array(bin.length);
			for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
			return arr.buffer;
		},
		encode: function(buf) {
			var bin = String.fromCharCode.apply(null, new Uint8Array(buf));
			return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
		}
	};

	var ERROR_MESSAGES = {
		'CHALLENGE_EXPIRED': 'Time limit exceeded. Please try again.',
		'INVALID_ORIGIN': 'Security Check Failed: Domain mismatch.',
		'CLONE_WARNING': 'Security Alert: This key may have been cloned!',
		'HELPER_NOT_FOUND': 'Passkey service is not installed.',
		'NotAllowedError': 'No matching passkey found on this device.',
		'AbortError': 'Operation cancelled.'
	};

	function rpcCall(endpoint, method, body) {
		var opts = {
			method: method || 'POST',
			headers: { 'Content-Type': 'application/json' }
		};
		if (body) opts.body = JSON.stringify(body);
		return fetch(RPC_BASE + endpoint, opts).then(function(r) { return r.json(); });
	}

	function showStatus(msg, isError) {
		var el = document.getElementById('webauthn-status');
		if (!el) return;
		el.style.display = '';
		el.className = 'alert-message' + (isError ? ' error' : '');
		el.textContent = msg;
	}

	function hideStatus() {
		var el = document.getElementById('webauthn-status');
		if (el) el.style.display = 'none';
	}

	function friendlyError(err) {
		if (err && err.name && ERROR_MESSAGES[err.name])
			return ERROR_MESSAGES[err.name];
		if (err && err.error && ERROR_MESSAGES[err.error])
			return ERROR_MESSAGES[err.error];
		if (err && err.message)
			return err.message;
		return 'Authentication failed. Please try again.';
	}

	function handlePasskeyLogin() {
		var btn = document.getElementById('webauthn-login-btn');
		if (btn) btn.disabled = true;
		hideStatus();
		showStatus('Waiting for passkey\u2026', false);

		rpcCall('login_begin', 'POST', { username: 'root' })
			.then(function(data) {
				if (data.error) throw data;

				var opts = data.publicKey || data;
				if (opts.challenge)
					opts.challenge = utils.decode(opts.challenge);
				if (opts.allowCredentials) {
					opts.allowCredentials.forEach(function(c) {
						if (c.id) c.id = utils.decode(c.id);
					});
				}

				return navigator.credentials.get({ publicKey: opts }).then(function(cred) {
					return { cred: cred, challengeId: data.challengeId };
				});
			})
			.then(function(result) {
				showStatus('Verifying\u2026', false);
				var cred = result.cred;

				var payload = {
					challengeId: result.challengeId,
					id: cred.id,
					type: cred.type,
					response: {
						authenticatorData: utils.encode(cred.response.authenticatorData),
						signature: utils.encode(cred.response.signature),
						clientDataJSON: utils.encode(cred.response.clientDataJSON)
					}
				};

				if (cred.response.userHandle)
					payload.response.userHandle = utils.encode(cred.response.userHandle);

				return rpcCall('login_finish', 'POST', payload);
			})
			.then(function(data) {
				if (data.error) throw data;
				if (data.success) {
					showStatus('Login successful! Redirecting\u2026', false);
					window.location.href = '/cgi-bin/luci/';
				} else {
					throw data;
				}
			})
			.catch(function(err) {
				showStatus(friendlyError(err), true);
				if (btn) btn.disabled = false;
			});
	}

	function init() {
		var btn = document.getElementById('webauthn-login-btn');
		if (!btn) return;

		if (!window.isSecureContext) {
			showStatus('Passkeys require HTTPS. Please configure SSL/TLS on this router.', true);
			btn.style.display = 'none';
			return;
		}

		if (!window.PublicKeyCredential) {
			btn.style.display = 'none';
			return;
		}

		rpcCall('health', 'GET')
			.then(function(data) {
				if (data && data.status === 'ok') {
					btn.disabled = false;
					btn.addEventListener('click', handlePasskeyLogin);
				} else {
					btn.style.display = 'none';
				}
			})
			.catch(function() {
				btn.style.display = 'none';
			});
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init);
	} else {
		init();
	}
})();
