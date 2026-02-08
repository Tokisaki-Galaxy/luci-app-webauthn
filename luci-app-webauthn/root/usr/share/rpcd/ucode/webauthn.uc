#!/usr/bin/env ucode

// LuCI WebAuthn RPC middleware
// Proxies requests to the webauthn-helper Rust CLI (v1.0)
//
// The CLI uses subcommand flags (not stdin JSON) for most commands,
// and only register-finish / login-finish read client JSON from stdin.
// All CLI responses use the envelope { success, data } or { success, error }.

'use strict';

import { popen, access, open, glob } from 'fs';
import { cursor } from 'uci';
import { connect } from 'ubus';
import { rand } from 'math';

const HELPER_BIN = '/usr/libexec/webauthn-helper';

function get_origin() {
	const uci = cursor();
	let origin = uci.get('webauthn', 'settings', 'origin');

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

function randomid(n) {
	let bytes = [];
	while (n-- > 0)
		push(bytes, sprintf('%02x', rand() % 256));
	return join('', bytes);
}

// Create a LuCI session for the given user after successful WebAuthn verification.
// Replicates what rpcd does during session login: create session, set user info,
// and grant ACL groups from /usr/share/rpcd/acl.d/*.
function create_luci_session(username) {
	let ubus_conn = connect();
	if (!ubus_conn)
		return null;

	let uci_inst = cursor();
	let timeout = +uci_inst.get('luci', 'sauth', 'sessiontime') || 3600;

	let sess = ubus_conn.call('session', 'create', { timeout: timeout });
	if (!sess?.ubus_rpc_session) {
		ubus_conn.disconnect();
		return null;
	}

	let sid = sess.ubus_rpc_session;
	let token = randomid(16);

	ubus_conn.call('session', 'set', {
		ubus_rpc_session: sid,
		values: { username: username, token: token }
	});

	// Grant ACLs by reading all acl.d JSON files, similar to rpcd login
	for (let aclfile in glob('/usr/share/rpcd/acl.d/*.json')) {
		let fd = open(aclfile, 'r');
		if (!fd) continue;

		let acl;
		try { acl = json(fd); } catch(e) { fd.close(); continue; }
		fd.close();

		for (let group_name, perms in acl) {
			if (group_name == 'unauthenticated')
				continue;

			// Grant access-group scope (what LuCI dispatcher checks)
			let ag_objects = [];
			if (perms?.read) push(ag_objects, [group_name, 'read']);
			if (perms?.write) push(ag_objects, [group_name, 'write']);
			if (length(ag_objects)) {
				ubus_conn.call('session', 'grant', {
					ubus_rpc_session: sid,
					scope: 'access-group',
					objects: ag_objects
				});
			}

			// Grant ubus scope (for RPC calls)
			let ubus_read = perms?.read?.ubus;
			let ubus_write = perms?.write?.ubus;
			let ubus_objects = [];

			if (type(ubus_read) == 'object') {
				for (let obj, methods in ubus_read) {
					if (type(methods) == 'array') {
						for (let m in methods)
							push(ubus_objects, [obj, m]);
					}
				}
			}
			if (type(ubus_write) == 'object') {
				for (let obj, methods in ubus_write) {
					if (type(methods) == 'array') {
						for (let m in methods)
							push(ubus_objects, [obj, m]);
					}
				}
			}
			if (length(ubus_objects)) {
				ubus_conn.call('session', 'grant', {
					ubus_rpc_session: sid,
					scope: 'ubus',
					objects: ubus_objects
				});
			}

			// Grant uci scope
			let uci_objects = [];
			if (type(perms?.read?.uci) == 'array') {
				for (let config in perms.read.uci)
					push(uci_objects, [config, 'read']);
			}
			if (type(perms?.write?.uci) == 'array') {
				for (let config in perms.write.uci)
					push(uci_objects, [config, 'write']);
			}
			if (length(uci_objects)) {
				ubus_conn.call('session', 'grant', {
					ubus_rpc_session: sid,
					scope: 'uci',
					objects: uci_objects
				});
			}

			// Grant file scope
			let file_objects = [];
			if (type(perms?.read?.file) == 'object') {
				for (let path, ops in perms.read.file) {
					if (type(ops) == 'array') {
						for (let op in ops)
							push(file_objects, [path, op]);
					}
				}
			}
			if (type(perms?.write?.file) == 'object') {
				for (let path, ops in perms.write.file) {
					if (type(ops) == 'array') {
						for (let op in ops)
							push(file_objects, [path, op]);
					}
				}
			}
			if (length(file_objects)) {
				ubus_conn.call('session', 'grant', {
					ubus_rpc_session: sid,
					scope: 'file',
					objects: file_objects
				});
			}

			// Grant cgi-io scope
			if (type(perms?.write?.['cgi-io']) == 'array') {
				let cgi_objects = [];
				for (let op in perms.write['cgi-io'])
					push(cgi_objects, ['cgi-io', op]);
				if (length(cgi_objects)) {
					ubus_conn.call('session', 'grant', {
						ubus_rpc_session: sid,
						scope: 'cgi-io',
						objects: cgi_objects
					});
				}
			}
		}
	}

	ubus_conn.disconnect();
	return { sid: sid, token: token };
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
			let origin = request.args.origin || get_origin();
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
			let origin = request.args.origin || get_origin();
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

	login_begin: {
		args: { username: 'username', origin: 'origin' },
		call: function(request) {
			let origin = request.args.origin || get_origin();
			let rp_id = get_rp_id(origin);
			let username = request.args.username || 'root';

			let cmd = sprintf('%s login-begin --username %s --rp-id %s',
				HELPER_BIN, esc(username), esc(rp_id));

			return unwrap(exec_helper(cmd));
		}
	},

	login_finish: {
		args: {
			challengeId: 'challengeId',
			id: 'id',
			type: 'type',
			response: {},
			origin: 'origin'
		},
		call: function(request) {
			let origin = request.args.origin || get_origin();
			let a = request.args;

			let cmd = sprintf('%s login-finish --challenge-id %s --origin %s',
				HELPER_BIN, esc(a.challengeId), esc(origin));

			let stdin_data = sprintf('%J', {
				id: a.id, rawId: a.id, type: a.type, response: a.response
			});

			let data = unwrap(exec_helper(cmd, stdin_data));
			if (data && !data.error) {
				data.success = true;

				// Create a LuCI session so the user is fully authenticated
				let username = data.username || 'root';
				let session = create_luci_session(username);
				if (session) {
					data.sessionId = session.sid;
					data.token = session.token;
				}
			}
			return data;
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
