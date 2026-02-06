#!/usr/bin/env ucode

// LuCI WebAuthn RPC middleware
// Proxies requests to the webauthn-helper Rust CLI

'use strict';

import { popen, access } from 'fs';
import { cursor } from 'uci';

const HELPER_BIN = '/usr/bin/webauthn-helper';

function get_origin() {
	// Origin is determined at request time from HTTP headers,
	// but in RPC context we read it from UCI or construct from system info.
	const uci = cursor();
	let origin = uci.get('webauthn', 'settings', 'origin');

	if (!origin) {
		// Fallback: construct from hostname
		let fd = popen('uci get system.@system[0].hostname 2>/dev/null');
		let hostname = fd ? trim(fd.read('all')) : 'openwrt';
		if (fd) fd.close();
		origin = 'https://' + hostname;
	}

	return origin;
}

function exec_helper(subcmd, args_str, stdin_data) {
	if (!access(HELPER_BIN)) {
		return { error: 'HELPER_NOT_FOUND', message: 'webauthn-helper binary not found' };
	}

	let origin = get_origin();
	let cmd = sprintf('%s %s --origin %s',
		HELPER_BIN,
		args_str ?? subcmd,
		origin);

	let fd;
	if (stdin_data) {
		let json_input = sprintf('%s', stdin_data);
		// Use printf to pipe JSON into stdin of the helper
		cmd = sprintf("printf '%%s' '%s' | %s",
			replace(json_input, "'", "'\\''"),
			cmd);
		fd = popen(cmd, 'r');
	} else {
		fd = popen(cmd, 'r');
	}

	if (!fd) {
		return { error: 'EXEC_FAILED', message: 'Failed to execute webauthn-helper' };
	}

	let output = fd.read('all');
	let exit_code = fd.close();

	let result;
	try {
		result = json(output);
	} catch (e) {
		result = { error: 'PARSE_ERROR', message: 'Invalid JSON response from helper', raw: output };
	}

	if (exit_code != 0 && !result.error) {
		result.error = 'HELPER_ERROR';
	}

	return result;
}

const methods = {
	health: {
		call: function() {
			return exec_helper('health-check');
		}
	},

	register_begin: {
		args: { username: 'username', userVerification: 'userVerification' },
		call: function(request) {
			let input = {};
			if (request.args.username)
				input.username = request.args.username;
			if (request.args.userVerification)
				input.userVerification = request.args.userVerification;

			return exec_helper('register-begin', 'register-begin', sprintf('%J', input));
		}
	},

	register_finish: {
		args: {
			challengeId: 'challengeId',
			deviceName: 'deviceName',
			id: 'id',
			type: 'type',
			response: 'response'
		},
		call: function(request) {
			return exec_helper('register-finish', 'register-finish', sprintf('%J', request.args));
		}
	},

	login_begin: {
		args: { username: 'username' },
		call: function(request) {
			let input = {};
			if (request.args.username)
				input.username = request.args.username;

			return exec_helper('login-begin', 'login-begin', sprintf('%J', input));
		}
	},

	login_finish: {
		args: {
			challengeId: 'challengeId',
			id: 'id',
			type: 'type',
			response: 'response'
		},
		call: function(request) {
			return exec_helper('login-finish', 'login-finish', sprintf('%J', request.args));
		}
	},

	manage_list: {
		call: function() {
			return exec_helper('credential-manage', 'credential-manage list');
		}
	},

	manage_delete: {
		args: { id: 'id' },
		call: function(request) {
			return exec_helper('credential-manage', 'credential-manage delete', sprintf('%J', { id: request.args.id }));
		}
	},

	manage_update: {
		args: { id: 'id', name: 'name' },
		call: function(request) {
			return exec_helper('credential-manage', 'credential-manage update',
				sprintf('%J', { id: request.args.id, name: request.args.name }));
		}
	}
};

return { 'luci.webauthn': methods };
