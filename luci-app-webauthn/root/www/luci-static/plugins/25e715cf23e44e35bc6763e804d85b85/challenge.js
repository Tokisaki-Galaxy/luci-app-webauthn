/* WebAuthn challenge UI for LuCI auth plugin */
(function() {
	'use strict';

	function decode(str) {
		var bin = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
		var arr = new Uint8Array(bin.length);
		for (var i = 0; i < bin.length; i++)
			arr[i] = bin.charCodeAt(i);
		return arr.buffer;
	}

	function encode(buf) {
		var bin = String.fromCharCode.apply(null, new Uint8Array(buf));
		return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
	}

	function showStatus(msg, isError) {
		var el = document.getElementById('webauthn-status');
		if (!el)
			return;
		el.style.display = '';
		el.className = 'alert-message' + (isError ? ' error' : '');
		el.textContent = msg;
	}

	function friendlyError(err) {
		if (err && err.name === 'NotAllowedError')
			return 'No matching passkey found on this device.';
		if (err && err.name === 'AbortError')
			return 'Operation cancelled.';
		if (err && err.message)
			return err.message;
		return 'Passkey authentication failed.';
	}

	function beginChallenge() {
		var tokenInput = document.querySelector('input[name="webauthn_auth_token"]');
		var responseInput = document.querySelector('input[name="webauthn_auth_response"]');
		var btn = document.getElementById('webauthn-login-btn');

		if (!tokenInput || !responseInput || !btn)
			return;

		if (!window.isSecureContext) {
			showStatus('Passkeys require HTTPS. Please configure SSL/TLS on this router.', true);
			return;
		}

		if (!window.PublicKeyCredential) {
			showStatus('Your browser does not support passkeys (WebAuthn).', true);
			return;
		}

		btn.disabled = true;
		showStatus('Waiting for passkey…', false);

		var token = tokenInput.value;
		var payload = {
			jsonrpc: '2.0',
			id: Date.now(),
			method: 'call',
			params: [
				'00000000000000000000000000000000',
				'luci.webauthn',
				'auth_challenge',
				{ token: token }
			]
		};

		fetch('/ubus', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(payload)
		})
		.then(function(r) { return r.json(); })
		.then(function(data) {
			if (!(data && data.result && data.result[0] === 0 && data.result[1] && data.result[1].publicKey))
				throw new Error('Unable to fetch passkey challenge');

			var opts = data.result[1].publicKey;
			if (opts.challenge)
				opts.challenge = decode(opts.challenge);
			if (opts.allowCredentials) {
				opts.allowCredentials.forEach(function(c) {
					if (c.id)
						c.id = decode(c.id);
				});
			}

			return navigator.credentials.get({ publicKey: opts });
		})
		.then(function(cred) {
			var response = {
				id: cred.id,
				type: cred.type,
				response: {
					authenticatorData: encode(cred.response.authenticatorData),
					signature: encode(cred.response.signature),
					clientDataJSON: encode(cred.response.clientDataJSON)
				}
			};

			if (cred.response.userHandle)
				response.response.userHandle = encode(cred.response.userHandle);

			responseInput.value = JSON.stringify(response);
			showStatus('Passkey verified. Logging in…', false);

			var form = document.querySelector('form[method="post"]');
			if (form)
				form.submit();
		})
		.catch(function(err) {
			showStatus(friendlyError(err), true);
			btn.disabled = false;
		});
	}

	function init() {
		var btn = document.getElementById('webauthn-login-btn');
		if (!btn)
			return;

		btn.addEventListener('click', beginChallenge);
	}

	if (document.readyState === 'loading')
		document.addEventListener('DOMContentLoaded', init);
	else
		init();
})();
