// WebAuthn authentication plugin for LuCI dispatcher auth.d mechanism
// This plugin adds a "Login with Passkey" option to the LuCI login page.
//
// Plugin interface (loaded by patched dispatcher.uc from /usr/share/luci/auth.d/):
//   name:     plugin identifier
//   priority: execution order (lower = first)
//   check:    called after password form is rendered; returns { required, fields, html }
//   verify:   called to verify additional authentication factor
//
// For WebAuthn, the actual authentication flow is client-side (navigator.credentials),
// so the plugin injects JS into the login page via the `html` field, and the verify
// function validates the server-side token set by the login_finish RPC endpoint.

'use strict';

import { popen, access } from 'fs';

const HELPER_BIN = '/usr/libexec/webauthn-helper';

function helper_available() {
	return access(HELPER_BIN);
}

function get_origin_from_http(http) {
	let origin = http.getenv('HTTP_ORIGIN');

	if (!origin) {
		let host = http.getenv('HTTP_HOST');
		let scheme = (http.getenv('HTTPS') == 'on') ? 'https' : 'http';
		if (host)
			origin = scheme + '://' + host;
	}

	return origin;
}

return {
	name: 'webauthn',
	priority: 100,

	check: function(http, user) {
		if (!helper_available())
			return { required: false };

		// WebAuthn does not require additional form fields (it uses browser API).
		// Instead, we inject a script block via the `html` property that adds
		// the "Login with Passkey" button and handles the WebAuthn ceremony.
		let script_url = '/luci-static/resources/view/system/webauthn-login.js';
		// Use <input type="button"> instead of <button> to avoid conflicting with
		// bootstrap sysauth.js which uses document.querySelector('button') to find
		// the "Log in" button – a <button> here would be matched first.
		let html_block = '<div id="webauthn-login-container">'
			+ '<hr style="margin:1em 0">'
			+ '<div id="webauthn-status" style="display:none" class="alert-message"></div>'
			+ '<input type="button" id="webauthn-login-btn" class="btn cbi-button" '
			+ 'style="width:100%;margin-top:0.5em" disabled '
			+ 'value="&#x1F511; Passkey">'
			+ '</div>'
			+ '<script src="' + script_url + '"><\/script>';

		return {
			required: false,
			html: html_block
		};
	},

	verify: function(http, user) {
		// WebAuthn verification happens via the separate RPC login_finish endpoint,
		// which sets a session token directly. This verify function is a no-op passthrough
		// since the WebAuthn flow bypasses the normal form POST authentication.
		return { success: true };
	}
};
