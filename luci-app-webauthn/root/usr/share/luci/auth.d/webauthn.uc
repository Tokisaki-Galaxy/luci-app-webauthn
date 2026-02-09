// WebAuthn authentication plugin for LuCI dispatcher auth.d mechanism
// This plugin adds a "Login with Passkey" option to the LuCI login page.
//
// Plugin interface (loaded by patched dispatcher.uc from /usr/share/luci/auth.d/):
//   name:     plugin identifier
//   priority: execution order (lower = first)
//   check:    called after password form is rendered; returns { required, fields, html }
//   verify:   called to verify additional authentication factor
//
// Two-phase login flow:
//   Phase 1 (rpcd): login_finish verifies the WebAuthn credential and writes a
//     verification token to /tmp/webauthn-verify-<token>.
//   Phase 2 (dispatcher/CGI): The frontend submits the token via form POST.
//     This check() function detects it, validates it, creates a ubus session
//     (safe here since we're in the uhttpd CGI process, not rpcd), and returns
//     the session to the dispatcher via the `session` field.

'use strict';

import { popen, access, open, unlink, glob } from 'fs';
import { connect } from 'ubus';
import { cursor } from 'uci';
import { openlog, syslog, LOG_INFO, LOG_WARNING, LOG_AUTHPRIV } from 'log';

openlog('webauthn');

const HELPER_BIN = '/usr/libexec/webauthn-helper';
const VERIFY_TOKEN_MAX_AGE = 120;

// Diagnostic logger: writes to syslog AND a debug file for troubleshooting.
// Syslog may be unavailable in some uhttpd contexts (logd not running, etc.).
function log_debug(msg) {
	syslog(LOG_INFO, msg);
	let fd = open('/tmp/webauthn-auth.log', 'a', 0600);
	if (fd) {
		fd.write(sprintf('[%d] %s\n', time(), msg));
		fd.close();
	}
}

function helper_available() {
	return access(HELPER_BIN);
}

function randomid(n) {
	let fd = open('/dev/urandom', 'r');
	if (fd) {
		let raw = fd.read(n);
		fd.close();
		if (raw) {
			let bytes = [];
			for (let i = 0; i < n; i++)
				push(bytes, sprintf('%02x', ord(raw, i)));
			return join('', bytes);
		}
	}
	return null;
}

// Create a LuCI session for the given user.
// Safe to call from the CGI/dispatcher context (uhttpd process), NOT from rpcd.
function create_session_for_user(username) {
	let ubus_conn = connect();
	if (!ubus_conn) {
		log_debug('webauthn: create_session_for_user: ubus connect() failed');
		return null;
	}

	let uci_inst = cursor();
	let timeout = +uci_inst.get('luci', 'sauth', 'sessiontime') || 3600;

	let sess = ubus_conn.call('session', 'create', { timeout: timeout });
	if (!sess?.ubus_rpc_session) {
		log_debug('webauthn: create_session_for_user: session.create failed');
		ubus_conn.disconnect();
		return null;
	}

	let sid = sess.ubus_rpc_session;
	let token = randomid(16);

	// session.set returns null/empty on success (no response body).
	// Do NOT check the return value — verify via session.get later.
	ubus_conn.call('session', 'set', {
		ubus_rpc_session: sid,
		values: { username: username, token: token }
	});

	// Grant ACLs by reading all acl.d JSON files
	for (let aclfile in glob('/usr/share/rpcd/acl.d/*.json')) {
		let fd = open(aclfile, 'r');
		if (!fd) continue;

		let acl;
		try { acl = json(fd); } catch(e) { fd.close(); continue; }
		fd.close();

		for (let group_name, perms in acl) {
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

			let ubus_objects = [];
			for (let scope_name in ['read', 'write']) {
				let ubus_perms = perms?.[scope_name]?.ubus;
				if (type(ubus_perms) == 'object') {
					for (let obj, methods in ubus_perms)
						if (type(methods) == 'array')
							for (let m in methods)
								push(ubus_objects, [obj, m]);
				}
			}
			if (length(ubus_objects)) {
				ubus_conn.call('session', 'grant', {
					ubus_rpc_session: sid,
					scope: 'ubus',
					objects: ubus_objects
				});
			}

			let uci_objects = [];
			if (type(perms?.read?.uci) == 'array')
				for (let config in perms.read.uci)
					push(uci_objects, [config, 'read']);
			if (type(perms?.write?.uci) == 'array')
				for (let config in perms.write.uci)
					push(uci_objects, [config, 'write']);
			if (length(uci_objects)) {
				ubus_conn.call('session', 'grant', {
					ubus_rpc_session: sid,
					scope: 'uci',
					objects: uci_objects
				});
			}

			let file_objects = [];
			for (let scope_name in ['read', 'write']) {
				let file_perms = perms?.[scope_name]?.file;
				if (type(file_perms) == 'object')
					for (let path, ops in file_perms)
						if (type(ops) == 'array')
							for (let op in ops)
								push(file_objects, [path, op]);
			}
			if (length(file_objects)) {
				ubus_conn.call('session', 'grant', {
					ubus_rpc_session: sid,
					scope: 'file',
					objects: file_objects
				});
			}

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

	// Fetch full session data for the dispatcher
	let sdat = ubus_conn.call('session', 'get', { ubus_rpc_session: sid });
	let sacl = ubus_conn.call('session', 'access', { ubus_rpc_session: sid });
	ubus_conn.disconnect();

	// Verify the token was actually stored (session.set has no return value,
	// so we confirm by reading back). The dispatcher's session_retrieve()
	// requires sdat.values.token to be a string.
	if (type(sdat?.values?.token) != 'string') {
		log_debug(sprintf('webauthn: session values missing after set, sid=%s got=%J',
			sid, sdat?.values));
		return null;
	}

	return {
		sid: sid,
		data: sdat.values,
		acls: length(sacl) ? sacl : {}
	};
}

// Validate a verification token written by login_finish (rpcd).
// Returns the username if valid, null otherwise.
function validate_verify_token(token) {
	// Sanitize token to prevent path traversal
	if (!match(token, /^[0-9a-f]{32}$/))
		return null;

	let path = '/tmp/webauthn-verify-' + token;
	let fd = open(path, 'r');
	if (!fd)
		return null;

	let data;
	try { data = json(fd); } catch(e) { }
	fd.close();

	// Always delete the token file (one-time use)
	unlink(path);

	if (!data || !data.username || !data.timestamp)
		return null;

	// Check timestamp (max age)
	if (time() - data.timestamp > VERIFY_TOKEN_MAX_AGE)
		return null;

	return data.username;
}

return {
	name: 'webauthn',
	priority: 100,

	check: function(http, user) {
		if (!helper_available())
			return { required: false };

		// Phase 2: Check for a verification token submitted by the frontend
		// after a successful WebAuthn ceremony (login_finish).
		let verify_token = http.formvalue('webauthn_verify_token');
		if (verify_token) {
			let remote_addr = http.getenv('REMOTE_ADDR') || '?';
			log_debug(sprintf('webauthn check: received verify_token from %s (len=%d)',
				remote_addr, length(verify_token)));

			let verified_user = validate_verify_token(verify_token);
			if (verified_user) {
				let session = create_session_for_user(verified_user);
				if (session) {
					log_debug(sprintf('luci: accepted webauthn login for %s from %s sid=%s',
						verified_user, remote_addr, session.sid));
					syslog(LOG_INFO|LOG_AUTHPRIV,
						sprintf("luci: accepted webauthn login for %s from %s",
							verified_user, remote_addr));
					return { required: false, session: session };
				}
				log_debug(sprintf('luci: webauthn session creation failed for %s from %s',
					verified_user, remote_addr));
				syslog(LOG_WARNING|LOG_AUTHPRIV,
					sprintf("luci: webauthn session creation failed for %s from %s",
						verified_user, remote_addr));
			} else {
				log_debug(sprintf('luci: webauthn token validation failed from %s',
					remote_addr));
				syslog(LOG_WARNING|LOG_AUTHPRIV,
					sprintf("luci: webauthn token validation failed from %s",
						remote_addr));
			}
			// Token invalid/expired — fall through to show login page
		}

		// Phase 1: Inject the Passkey button into the login page.
		// Use <input type="button"> instead of <button> to avoid conflicting with
		// bootstrap sysauth.js which uses document.querySelector('button') to find
		// the "Log in" button – a <button> here would be matched first.
		let script_url = '/luci-static/resources/view/system/webauthn-login.js';
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
		return { success: true };
	}
};
