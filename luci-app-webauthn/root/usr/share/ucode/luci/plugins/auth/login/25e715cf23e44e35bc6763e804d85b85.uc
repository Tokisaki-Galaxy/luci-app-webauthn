/*
WebAuthn authentication plugin for LuCI auth login plugins.
Implements challenge generation in check() and assertion verification in verify().
*/

'use strict';

import { popen, access, open, unlink } from 'fs';
import { cursor } from 'uci';
import { syslog, LOG_INFO, LOG_WARNING, LOG_AUTHPRIV } from 'log';

const PLUGIN_UUID = '25e715cf23e44e35bc6763e804d85b85';
const HELPER_BIN = '/usr/libexec/webauthn-helper';
const CHALLENGE_MAX_AGE = 120;
const CHALLENGE_PATH_PREFIX = '/tmp/webauthn-auth-';

function esc(s) {
	return "'" + replace(s ?? '', "'", "'\\''") + "'";
}

function helper_available() {
	return access(HELPER_BIN);
}

function plugin_enabled() {
	let uci = cursor();
	return uci.get('luci_plugins', PLUGIN_UUID, 'enabled') == '1';
}

function get_origin(http) {
	let uci = cursor();
	let cfg_origin = uci.get('luci_plugins', PLUGIN_UUID, 'origin');
	if (cfg_origin)
		return cfg_origin;

	let host = http.getenv('HTTP_HOST') || http.getenv('SERVER_NAME') || 'openwrt';
	let scheme = (http.getenv('HTTPS') == 'on') ? 'https' : 'http';

	return `${scheme}://${host}`;
}

function get_rp_id(origin) {
	let rest = replace(origin, /^https?:\/\//, '');
	let host = split(rest, '/')[0];
	let parts = split(host, ':');
	return parts[0];
}

function exec_helper(cmd, stdin_data) {
	let full_cmd = stdin_data ? sprintf("printf '%%s' %s | %s", esc(stdin_data), cmd) : cmd;
	let fd = popen(full_cmd, 'r');
	if (!fd)
		return { error: 'EXEC_FAILED', message: 'Failed to execute webauthn-helper' };

	let output = fd.read('all');
	fd.close();

	try {
		return json(output);
	}
	catch (e) {
		return { error: 'PARSE_ERROR', message: 'Invalid JSON from helper' };
	}
}

function unwrap(result) {
	if (result == null)
		return result;

	if (type(result.error) == 'string')
		return result;

	if (result.success == false && result.error)
		return { error: result.error.code, message: result.error.message };

	if (result.success == true)
		return result.data;

	return result;
}

function randomid(n) {
	let fd = open('/dev/urandom', 'r');
	if (!fd)
		return null;

	let raw = fd.read(n);
	fd.close();

	if (!raw)
		return null;

	let bytes = [];
	for (let i = 0; i < n; i++)
		push(bytes, sprintf('%02x', ord(raw, i)));

	return join('', bytes);
}

function write_challenge_state(username, challenge_id, public_key, origin) {
	let token = randomid(16);
	if (!token)
		return null;

	let path = CHALLENGE_PATH_PREFIX + token;
	let fd = open(path, 'w', 0600);
	if (!fd)
		return null;

	fd.write(sprintf('%J', {
		username: username,
		challengeId: challenge_id,
		publicKey: public_key,
		origin: origin,
		timestamp: time()
	}));
	fd.close();

	return token;
}

function read_challenge_state(token, consume) {
	if (!match(token, /^[0-9a-f]{32}$/))
		return null;

	let path = CHALLENGE_PATH_PREFIX + token;
	let fd = open(path, 'r');
	if (!fd)
		return null;

	let data = null;
	try { data = json(fd); } catch (e) {}
	fd.close();

	if (consume)
		unlink(path);

	if (!data?.username || !data?.challengeId || !data?.publicKey || !data?.origin || !data?.timestamp)
		return null;

	if (time() - data.timestamp > CHALLENGE_MAX_AGE)
		return null;

	return data;
}

function has_registered_credentials(username) {
	let cmd = sprintf('%s credential-manage list --username %s', HELPER_BIN, esc(username));
	let data = unwrap(exec_helper(cmd));

	if (data?.error) {
		syslog(LOG_WARNING,
			sprintf("luci: webauthn credential list error for %s: %s",
				username, data.message || data.error));
		return false;
	}

	return (type(data) == 'array' && length(data) > 0);
}

return {
	priority: 20,

	check: function(http, user) {
		if (!plugin_enabled() || !helper_available())
			return { required: false };

		if (!has_registered_credentials(user))
			return { required: false };

		let origin = get_origin(http);
		let rp_id = get_rp_id(origin);
		let cmd = sprintf('%s login-begin --username %s --rp-id %s',
			HELPER_BIN, esc(user), esc(rp_id));
		let begin = unwrap(exec_helper(cmd));

		if (begin?.error) {
			syslog(LOG_WARNING|LOG_AUTHPRIV,
				sprintf("luci: webauthn login-begin failed for %s from %s: %s",
					user || '?', http.getenv('REMOTE_ADDR') || '?', begin.message || begin.error));
			return {
				required: true,
				fields: [],
				message: begin.message || 'Passkey challenge generation failed'
			};
		}

		let public_key = begin.publicKey || begin;
		let challenge_id = begin.challengeId;
		if (!challenge_id || type(public_key) != 'object')
			return {
				required: true,
				fields: [],
				message: 'Passkey challenge is invalid'
			};

		let token = write_challenge_state(user, challenge_id, public_key, origin);
		if (!token)
			return {
				required: true,
				fields: [],
				message: 'Passkey challenge state setup failed'
			};

		return {
			required: true,
			fields: [],
			message: 'Confirm your passkey to complete login.',
			html: '<div id="webauthn-login-container">'
				+ '<input type="hidden" name="webauthn_auth_token" value="' + token + '">'
				+ '<input type="hidden" name="webauthn_auth_response" value="">'
				+ '<div id="webauthn-status" style="display:none" class="alert-message"></div>'
				+ '<input type="button" id="webauthn-login-btn" class="btn cbi-button" '
				+ 'style="width:100%;margin-top:0.5em" value="&#x1F511; Passkey">'
				+ '</div>',
			assets: [
				`/luci-static/plugins/${PLUGIN_UUID}/challenge.js`
			]
		};
	},

	verify: function(http, user) {
		let token = http.formvalue('webauthn_auth_token');
		let response_json = http.formvalue('webauthn_auth_response');

		if (!token || !response_json)
			return { success: false, message: 'Passkey response is required' };

		let state = read_challenge_state(token, false);
		if (!state)
			return { success: false, message: 'Passkey challenge expired or invalid' };

		if (state.username != user)
			return { success: false, message: 'Passkey challenge user mismatch' };

		let assertion = null;
		try { assertion = json(response_json); } catch (e) {}

		if (!(assertion?.id && assertion?.type && assertion?.response))
			return { success: false, message: 'Passkey response format is invalid' };

		// Consume challenge only after basic request validation to avoid burning
		// valid challenges on malformed submissions.
		state = read_challenge_state(token, true);
		if (!state)
			return { success: false, message: 'Passkey challenge expired or invalid' };

		let cmd = sprintf('%s login-finish --challenge-id %s --origin %s',
			HELPER_BIN, esc(state.challengeId), esc(state.origin));
		let data = unwrap(exec_helper(cmd, sprintf('%J', {
			id: assertion.id,
			rawId: assertion.id,
			type: assertion.type,
			response: assertion.response
		})));

		if (data?.error) {
			syslog(LOG_WARNING|LOG_AUTHPRIV,
				sprintf("luci: webauthn login-finish failed for %s from %s: %s",
					user || '?', http.getenv('REMOTE_ADDR') || '?', data.message || data.error));
			return { success: false, message: data.message || 'Passkey verification failed' };
		}

		if (data?.username && data.username != user)
			return { success: false, message: 'Passkey verification user mismatch' };

		syslog(LOG_INFO|LOG_AUTHPRIV,
			sprintf("luci: webauthn verification succeeded for %s from %s",
				user || '?', http.getenv('REMOTE_ADDR') || '?'));

		return { success: true };
	}
};
