'use strict';
'require view';
'require dom';
'require rpc';
'require ui';

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
	'CHALLENGE_EXPIRED': _('Time limit exceeded. Please try again.'),
	'INVALID_ORIGIN':    _('Security Check Failed: Domain mismatch.'),
	'CLONE_WARNING':     _('Security Alert: This key may have been cloned!'),
	'USER_CANCELLED':    _('Operation cancelled.'),
	'NOT_ALLOWED_ERROR': _('No matching passkey found on this device.')
};

var callHealth = rpc.declare({
	object: 'luci.webauthn',
	method: 'health',
	expect: { }
});

var callManageList = rpc.declare({
	object: 'luci.webauthn',
	method: 'manage_list',
	expect: { }
});

var callManageDelete = rpc.declare({
	object: 'luci.webauthn',
	method: 'manage_delete',
	params: [ 'id' ],
	expect: { }
});

var callManageUpdate = rpc.declare({
	object: 'luci.webauthn',
	method: 'manage_update',
	params: [ 'id', 'name' ],
	expect: { }
});

var callRegisterBegin = rpc.declare({
	object: 'luci.webauthn',
	method: 'register_begin',
	params: [ 'username', 'userVerification', 'origin' ],
	expect: { }
});

var callRegisterFinish = rpc.declare({
	object: 'luci.webauthn',
	method: 'register_finish',
	params: [ 'challengeId', 'deviceName', 'id', 'type', 'response', 'origin' ],
	expect: { }
});

function friendlyError(err) {
	if (err && err.error && ERROR_MESSAGES[err.error])
		return ERROR_MESSAGES[err.error];
	if (err && err.name === 'NotAllowedError')
		return ERROR_MESSAGES['NOT_ALLOWED_ERROR'];
	if (err && err.name === 'AbortError')
		return ERROR_MESSAGES['USER_CANCELLED'];
	if (err && err.message)
		return err.message;
	return _('An unknown error occurred.');
}

function formatDate(ts) {
	if (!ts) return '-';
	var d = new Date(ts);
	if (isNaN(d.getTime())) return ts;
	return d.toISOString().substring(0, 10);
}

function formatRelativeTime(ts) {
	if (!ts) return _('Never');
	var d = new Date(ts);
	if (isNaN(d.getTime())) return ts;
	var now = new Date();
	var diff = Math.floor((now - d) / 1000);
	if (diff < 60) return _('Just now');
	if (diff < 3600) return _('%d minutes ago').format(Math.floor(diff / 60));
	if (diff < 86400) return _('%d hours ago').format(Math.floor(diff / 3600));
	if (diff < 2592000) return _('%d days ago').format(Math.floor(diff / 86400));
	return formatDate(ts);
}

return view.extend({
	load: function() {
		return Promise.all([
			callHealth().catch(function() { return {}; }),
			callManageList().catch(function() { return { credentials: [] }; })
		]);
	},

	renderCredentialTable: function(credentials) {
		var self = this;

		var table = E('table', { 'class': 'table cbi-section-table' }, [
			E('tr', { 'class': 'tr table-titles' }, [
				E('th', { 'class': 'th' }, _('Device Name')),
				E('th', { 'class': 'th' }, _('Registered')),
				E('th', { 'class': 'th' }, _('Last Used')),
				E('th', { 'class': 'th' }, _('Verified')),
				E('th', { 'class': 'th' }, _('Actions'))
			])
		]);

		if (!credentials || credentials.length === 0) {
			table.appendChild(E('tr', { 'class': 'tr placeholder' }, [
				E('td', { 'class': 'td', 'colspan': '5' },
					_('No passkeys registered. Click "Register New Passkey" to add one.'))
			]));
			return table;
		}

		credentials.forEach(function(cred) {
			var nameInput = E('input', {
				'type': 'text',
				'class': 'cbi-input-text',
				'value': cred.deviceName || '',
				'data-id': cred.id,
				'style': 'width:100%'
			});

			nameInput.addEventListener('blur', function() {
				var newName = this.value;
				var credId = this.getAttribute('data-id');
				if (newName !== cred.deviceName) {
					callManageUpdate(credId, newName).then(function() {
						ui.addNotification(null, E('p', _('Device name updated.')), 'info');
					}).catch(function(err) {
						ui.addNotification(null, E('p', friendlyError(err)), 'error');
					});
				}
			});

			nameInput.addEventListener('keydown', function(ev) {
				if (ev.key === 'Enter') this.blur();
			});

			var deleteBtn = E('button', {
				'class': 'btn cbi-button cbi-button-remove',
				'data-id': cred.id,
				'click': function() {
					var credId = this.getAttribute('data-id');
					if (confirm(_('Are you sure you want to delete this passkey?'))) {
						callManageDelete(credId).then(function() {
							self.refreshTable();
						}).catch(function(err) {
							ui.addNotification(null, E('p', friendlyError(err)), 'error');
						});
					}
				}
			}, _('Delete'));

			var verifiedIcon = cred.userVerified
				? E('span', { 'style': 'color:green' }, '\u2714')
				: E('span', { 'style': 'color:gray' }, '\u2718');

			table.appendChild(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, [ nameInput ]),
				E('td', { 'class': 'td' }, formatDate(cred.createdAt)),
				E('td', { 'class': 'td' }, formatRelativeTime(cred.lastUsedAt)),
				E('td', { 'class': 'td' }, [ verifiedIcon ]),
				E('td', { 'class': 'td' }, [ deleteBtn ])
			]));
		});

		return table;
	},

	refreshTable: function() {
		var self = this;
		return callManageList().then(function(data) {
			var container = document.getElementById('webauthn-table-container');
			if (container) {
				dom.content(container, self.renderCredentialTable(data.credentials || []));
			}
		}).catch(function(err) {
			ui.addNotification(null, E('p', friendlyError(err)), 'error');
		});
	},

	handleRegister: function() {
		var self = this;

		if (!window.isSecureContext) {
			ui.addNotification(null,
				E('p', _('Passkeys require HTTPS. Please configure SSL/TLS on this router.')),
				'error');
			return;
		}

		if (!window.PublicKeyCredential) {
			ui.addNotification(null,
				E('p', _('Your browser does not support passkeys (WebAuthn).')),
				'error');
			return;
		}

		var deviceName = prompt(_('Enter a name for this passkey (e.g. "My Laptop"):'),
			'My Device');
		if (deviceName === null) return;

		return callRegisterBegin('root', 'preferred', window.location.origin)
			.then(function(data) {
				if (data.error) throw data;

				var opts = data.publicKey || data;
				if (opts.challenge)
					opts.challenge = utils.decode(opts.challenge);
				if (opts.user && opts.user.id)
					opts.user.id = utils.decode(opts.user.id);
				if (opts.excludeCredentials) {
					opts.excludeCredentials.forEach(function(c) {
						if (c.id) c.id = utils.decode(c.id);
					});
				}

				return navigator.credentials.create({ publicKey: opts }).then(function(cred) {
					return { cred: cred, challengeId: data.challengeId };
				});
			})
			.then(function(result) {
				var cred = result.cred;
				return callRegisterFinish(
					result.challengeId,
					deviceName,
					cred.id,
					cred.type,
					{
						clientDataJSON: utils.encode(cred.response.clientDataJSON),
						attestationObject: utils.encode(cred.response.attestationObject)
					},
					window.location.origin
				);
			})
			.then(function(data) {
				if (data.error) throw data;
				ui.addNotification(null, E('p', _('Passkey registered successfully!')), 'info');
				return self.refreshTable();
			})
			.catch(function(err) {
				ui.addNotification(null, E('p', friendlyError(err)), 'error');
			});
	},

	render: function(data) {
		var self = this;
		var health = data[0] || {};
		var manageData = data[1] || {};
		var credentials = manageData.credentials || [];

		var children = [
			E('h2', _('Passkey Management')),
			E('div', { 'class': 'cbi-map-descr' },
				_('Manage WebAuthn passkeys for passwordless login to this router.'))
		];

		if (!window.isSecureContext) {
			children.push(E('div', { 'class': 'alert-message warning' },
				_('Passkeys require HTTPS. Please configure SSL/TLS on this router.')));
		} else if (health.error) {
			children.push(E('div', { 'class': 'alert-message warning' },
				_('WebAuthn service is not available: %s').format(
					health.message || health.error)));
		} else if (!window.PublicKeyCredential) {
			children.push(E('div', { 'class': 'alert-message warning' },
				_('Your browser does not support passkeys (WebAuthn).')));
		}

		var registerBtn = E('button', {
			'class': 'btn cbi-button cbi-button-positive',
			'click': function() { self.handleRegister(); },
			'disabled': (!window.isSecureContext || !!health.error || !window.PublicKeyCredential) || null
		}, [ '\u{1F511} ', _('Register New Passkey') ]);

		children.push(E('div', { 'class': 'cbi-section' }, [
			E('div', { 'id': 'webauthn-table-container' }, [
				this.renderCredentialTable(credentials)
			]),
			E('div', { 'class': 'cbi-page-actions', 'style': 'margin-top:1em' }, [
				registerBtn
			])
		]));

		return E('div', { 'class': 'cbi-map' }, children);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
