// LuCI Authentication Plugin Module
// Extracted from dispatcher.uc to minimize patch delta.
// Provides: load_auth_plugins, get_auth_challenge, verify_auth_challenge
//
// Copyright 2025 Tokisaki-Galaxy
// Licensed under the Apache License 2.0

'use strict';

import { glob } from 'fs';
import { cursor } from 'uci';
import { syslog, LOG_INFO, LOG_WARNING, LOG_AUTHPRIV } from 'log';

const AUTH_PLUGINS_DIR = '/usr/share/luci/auth.d';

let cached_plugins = null;

function load_auth_plugins() {
	let uci = cursor();

	if (uci.get('luci', 'main', 'external_auth') != '1')
		return [];

	if (cached_plugins != null)
		return cached_plugins;

	cached_plugins = [];

	for (let path in glob(AUTH_PLUGINS_DIR + '/*.uc')) {
		try {
			let code = loadfile(path);
			if (!code)
				continue;

			let plugin = call(code);
			if (type(plugin) == 'object' &&
				type(plugin.name) == 'string' &&
				type(plugin.check) == 'function' &&
				type(plugin.verify) == 'function') {
				let is_disabled = uci.get('luci', 'sauth', `${plugin.name}_disabled`);
				if (is_disabled == '1' || is_disabled === true)
					continue;

				push(cached_plugins, plugin);
			}
		}
		catch (e) {
			// Skip invalid plugins silently
		}
	}

	cached_plugins = sort(cached_plugins, (a, b) => (a.priority ?? 50) - (b.priority ?? 50));

	return cached_plugins;
}

// Collect UI elements (fields, html, messages) from auth plugins.
// Returns { pending, plugin, fields, message, html } when required plugins exist,
// or { pending: false, html } when only optional plugins inject UI.
function get_auth_challenge(http, user) {
	let plugins = load_auth_plugins();
	let all_fields = [];
	let all_html_parts = [];
	let all_messages = [];
	let extra_html_parts = [];
	let first_plugin = null;
	let auth_session = null;

	for (let plugin in plugins) {
		try {
			let result = plugin.check(http, user);
			if (result?.session && !auth_session)
				auth_session = result.session;
			if (result?.required) {
				if (!first_plugin)
					first_plugin = plugin;

				if (result.fields)
					push(all_fields, ...result.fields);

				if (result.html)
					push(all_html_parts, result.html);

				if (result.message)
					push(all_messages, result.message);
			} else if (result?.html) {
				push(extra_html_parts, result.html);
			}
		}
		catch (e) {
			syslog(LOG_WARNING,
				sprintf("luci: auth plugin '%s' check error: %s", plugin.name, e));
		}
	}

	let combined_html = join('', [...all_html_parts, ...extra_html_parts]);

	if (first_plugin) {
		return {
			pending: true,
			plugin: first_plugin,
			fields: all_fields,
			message: join(' ', all_messages),
			html: combined_html,
			session: auth_session
		};
	}

	return { pending: false, html: length(combined_html) ? combined_html : null, session: auth_session };
}

// Verify all required auth plugin challenges after password auth succeeds.
// Returns { success: true } if all pass, or { success: false, message } on first failure.
function verify_auth_challenge(http, user) {
	let plugins = load_auth_plugins();

	for (let plugin in plugins) {
		try {
			let check_result = plugin.check(http, user);
			if (!check_result?.required)
				continue;

			let verify_result = plugin.verify(http, user);
			if (!verify_result?.success) {
				syslog(LOG_WARNING|LOG_AUTHPRIV,
					sprintf("luci: auth plugin '%s' verification failed for %s from %s",
						plugin.name, user || '?', http.getenv('REMOTE_ADDR') || '?'));
				return {
					success: false,
					message: verify_result?.message ?? 'Authentication failed',
					plugin: plugin
				};
			}

			syslog(LOG_INFO|LOG_AUTHPRIV,
				sprintf("luci: auth plugin '%s' verification succeeded for %s from %s",
					plugin.name, user || '?', http.getenv('REMOTE_ADDR') || '?'));
		}
		catch (e) {
			syslog(LOG_WARNING,
				sprintf("luci: auth plugin '%s' verify error: %s", plugin.name, e));
			return {
				success: false,
				message: 'Authentication plugin error'
			};
		}
	}

	return { success: true };
}

export { load_auth_plugins, get_auth_challenge, verify_auth_challenge };
