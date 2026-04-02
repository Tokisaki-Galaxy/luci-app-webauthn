#!/usr/bin/env ucode

// LuCI WebAuthn RPC middleware
// Proxies requests to the webauthn-helper Rust CLI (v1.0)
//
// The CLI uses subcommand flags (not stdin JSON) for most commands,
// and only register-finish / login-finish read client JSON from stdin.
// All CLI responses use the envelope { success, data } or { success, error }.

'use strict';

import { popen, access, open } from 'fs';
import { cursor } from 'uci';

const HELPER_BIN = '/usr/libexec/webauthn-helper';

const PLUGIN_UUID = '25e715cf23e44e35bc6763e804d85b85';
const CHALLENGE_PATH_PREFIX = '/tmp/webauthn-auth-';
const CHALLENGE_MAX_AGE = 120;

function plugin_origin() {
	const uci = cursor();
	let origin = uci.get('luci_plugins', PLUGIN_UUID, 'origin');

	if (!origin) {
		let fd = popen('uci get system.@system[0].hostname 2>/dev/null');
		let hostname = fd ? trim(fd.read('all')) : 'openwrt';
		if (fd) fd.close();
		origin = 'https://' + hostname;
	}

	return origin;
}

// Extract hostname (rp-id) from an origin URL, stripping scheme and port.
function get_rp_id(origin) {
	let rest = replace(origin, /^https?:\/\//, '');
	let host = split(rest, '/')[0];
	let parts = split(host, ':');
	return parts[0];
}

// Shell-escape a value using POSIX single-quote wrapping.
// Inside single quotes all characters are literal; only ' itself needs
// the break-escape-reopen sequence: ' → '\''
function esc(s) {
	return "'" + replace(s ?? '', "'", "'\\''") + "'";
}

// Execute the helper binary and return parsed JSON.
// `cmd` is the full command string; `stdin_data` is optional JSON piped to stdin.
function exec_helper(cmd, stdin_data) {
	if (!access(HELPER_BIN)) {
		return { error: 'HELPER_NOT_FOUND', message: 'webauthn-helper binary not found' };
	}

	let full_cmd;
	if (stdin_data) {
		full_cmd = sprintf("printf '%%s' %s | %s", esc(stdin_data), cmd);
	} else {
		full_cmd = cmd;
	}

	let fd = popen(full_cmd, 'r');
	if (!fd) {
		return { error: 'EXEC_FAILED', message: 'Failed to execute webauthn-helper' };
	}

	let output = fd.read('all');
	fd.close();

	let result;
	try {
		result = json(output);
	} catch (e) {
		return { error: 'PARSE_ERROR', message: 'Invalid JSON from helper' };
	}

	return result;
}

// Unwrap the { success, data } / { success, error } envelope from the CLI.
// Returns the inner `data` on success, or { error, message } on failure.
function unwrap(result) {
	if (result == null)
		return result;

	// Already a middleware-level error (no envelope)
	if (type(result.error) == 'string')
		return result;

	// CLI error: { success: false, error: { code, message } }
	if (result.success == false && result.error)
		return { error: result.error.code, message: result.error.message };

	// CLI success: { success: true, data: <payload> }
	if (result.success == true)
		return result.data;

	return result;
}

function read_challenge_state(token) {
	if (!match(token, /^[0-9a-f]{32}$/))
		return null;

	let path = CHALLENGE_PATH_PREFIX + token;
	let fd = open(path, 'r');
	if (!fd)
		return null;

	let data = null;
	try { data = json(fd); } catch (e) {}
	fd.close();

	if (!data?.username || !data?.publicKey || !data?.challengeId || !data?.timestamp || !data?.origin)
		return null;

	if (time() - data.timestamp > CHALLENGE_MAX_AGE)
		return null;

	return data;
}

const methods = {
	health: {
		call: function() {
			let cmd = sprintf('%s health-check', HELPER_BIN);
			return unwrap(exec_helper(cmd));
		}
	},

	register_begin: {
		args: { username: 'username', userVerification: 'userVerification', origin: 'origin' },
		call: function(request) {
			let origin = request.args.origin || plugin_origin();
			let rp_id = get_rp_id(origin);
			let username = request.args.username || 'root';
			let uv = request.args.userVerification || 'preferred';

			let cmd = sprintf('%s register-begin --username %s --rp-id %s --user-verification %s',
				HELPER_BIN, esc(username), esc(rp_id), esc(uv));

			return unwrap(exec_helper(cmd));
		}
	},

	register_finish: {
		args: {
			challengeId: 'challengeId',
			deviceName: 'deviceName',
			id: 'id',
			type: 'type',
			response: {},
			origin: 'origin'
		},
		call: function(request) {
			let origin = request.args.origin || plugin_origin();
			let a = request.args;

			let cmd = sprintf('%s register-finish --challenge-id %s --origin %s --device-name %s',
				HELPER_BIN, esc(a.challengeId), esc(origin), esc(a.deviceName));

			// WebAuthn spec: rawId is the binary form, id is base64url.
			// In JSON both carry the same base64url value; the CLI expects both.
			let stdin_data = sprintf('%J', {
				id: a.id, rawId: a.id, type: a.type, response: a.response
			});

			return unwrap(exec_helper(cmd, stdin_data));
		}
	},

	auth_challenge: {
		args: { token: 'token' },
		call: function(request) {
			let state = read_challenge_state(request.args.token);
			if (!state)
				return { error: 'CHALLENGE_INVALID', message: 'Challenge not found or expired' };

			return {
				challengeId: state.challengeId,
				publicKey: state.publicKey,
				origin: state.origin
			};
		}
	},

	manage_list: {
		call: function() {
			let cmd = sprintf('%s credential-manage list --username %s',
				HELPER_BIN, esc('root'));

			let data = unwrap(exec_helper(cmd));

			// Backend returns an array; frontend expects { credentials: [...] }.
			// Also map credentialId -> id for each item.
			if (type(data) == 'array') {
				for (let i = 0; i < length(data); i++) {
					if (data[i].credentialId)
						data[i].id = data[i].credentialId;
				}
				return { credentials: data };
			}

			return data;
		}
	},

	manage_delete: {
		args: { id: 'id' },
		call: function(request) {
			let cmd = sprintf('%s credential-manage delete --id %s',
				HELPER_BIN, esc(request.args.id));

			return unwrap(exec_helper(cmd));
		}
	},

	manage_update: {
		args: { id: 'id', name: 'name' },
		call: function(request) {
			let cmd = sprintf('%s credential-manage update --id %s --name %s',
				HELPER_BIN, esc(request.args.id), esc(request.args.name));

			return unwrap(exec_helper(cmd));
		}
	}
};

return { 'luci.webauthn': methods };
