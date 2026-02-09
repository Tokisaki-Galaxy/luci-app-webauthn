/* WebAuthn Login Page Enhancement
 * Loaded on the LuCI login page via the auth.d plugin HTML injection.
 * Handles the WebAuthn authentication ceremony (navigator.credentials.get).
 *
 * Copyright 2025 Tokisaki-Galaxy
 * Licensed under the Apache License 2.0
 */

(function() {
	'use strict';

	var UBUS_URL = '/ubus';
	var ANON_SID = '00000000000000000000000000000000'; /* ubus anonymous session */
	var rpcId = 1;

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

	function ubusCall(object, method, params) {
		return fetch(UBUS_URL, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: rpcId++,
				method: 'call',
				params: [ANON_SID, object, method, params || {}]
			})
		}).then(function(r) { return r.json(); }).then(function(data) {
			if (data.result && data.result[0] === 0)
				return data.result[1] || {};
			if (data.error)
				throw { error: 'RPC_ERROR', message: data.error.message || 'RPC call failed' };
			throw { error: 'RPC_ERROR', message: 'Unexpected response' };
		});
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

		ubusCall('luci.webauthn', 'login_begin', { username: 'root', origin: window.location.origin })
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
					},
					origin: window.location.origin
				};

				if (cred.response.userHandle)
					payload.response.userHandle = utils.encode(cred.response.userHandle);

				return ubusCall('luci.webauthn', 'login_finish', payload);
			})
			.then(function(data) {
				if (data.error) throw data;
				if (data.success && data.verifyToken) {
					showStatus('Login successful! Redirecting\u2026', false);
					submitVerifyToken(data.verifyToken, data.username);
				} else {
					throw data;
				}
			})
			.catch(function(err) {
				showStatus(friendlyError(err), true);
				if (btn) btn.disabled = false;
			});
	}

	function submitVerifyToken(token, username) {
		// Phase 2: Submit the verify token to the CGI dispatcher.
		// The auth.d plugin will validate it and create a session.
		// Use fetch() for reliability: it processes Set-Cookie from 302
		// responses and gives us full control over error handling.
		// Falls back to form.submit() if fetch fails.
		var scriptName = (typeof L !== 'undefined' && L.env && L.env.scriptname)
			? L.env.scriptname : '/cgi-bin/luci';
		var submitUrl = scriptName + '/';

		var formBody = 'luci_username=' + encodeURIComponent(username || 'root')
			+ '&luci_password='
			+ '&webauthn_verify_token=' + encodeURIComponent(token);

		fetch(submitUrl, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: formBody,
			redirect: 'follow',
			credentials: 'same-origin'
		}).then(function(resp) {
			if (resp.ok || resp.redirected) {
				window.location.replace(resp.url || submitUrl);
			} else {
				showStatus('Login failed (server returned ' + resp.status + '). Please try again.', true);
				var btn = document.getElementById('webauthn-login-btn');
				if (btn) btn.disabled = false;
			}
		}).catch(function() {
			// Network error: fall back to traditional form submission
			var form = document.querySelector('form[method="post"]');
			if (form) {
				var input = document.createElement('input');
				input.type = 'hidden';
				input.name = 'webauthn_verify_token';
				input.value = token;
				form.appendChild(input);
				var ufield = form.querySelector('[name="luci_username"]');
				if (ufield) ufield.value = username || ufield.value;
				form.submit();
			} else {
				window.location.href = submitUrl
					+ '?webauthn_verify_token=' + encodeURIComponent(token);
			}
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

		ubusCall('luci.webauthn', 'health')
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
