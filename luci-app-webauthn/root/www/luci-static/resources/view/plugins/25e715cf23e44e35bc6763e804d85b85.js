'use strict';
'require baseclass';
'require form';

return baseclass.extend({
	class: 'auth',
	class_i18n: _('Authentication'),

	type: 'login',
	type_i18n: _('Login'),

	name: 'WebAuthn Passkey',
	id: '25e715cf23e44e35bc6763e804d85b85',
	title: _('WebAuthn Passkey Authentication'),
	description: _('Adds passkey verification as an additional authentication factor for LuCI login. ' +
	               'Use the WebAuthn management RPC APIs to register and manage credentials.'),

	addFormOptions: function(s) {
		var o;

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = o.disabled;
		o.rmempty = false;

		o = s.option(form.Value, 'priority', _('Priority'),
			_('Execution order for this plugin. Lower values run earlier.'));
		o.depends('enabled', '1');
		o.datatype = 'integer';
		o.placeholder = '20';
		o.rmempty = true;

		o = s.option(form.Value, 'origin', _('Origin (optional override)'),
			_('Optional origin override for WebAuthn verification, e.g. https://router.example.com'));
		o.depends('enabled', '1');
		o.placeholder = 'https://openwrt.local';
		o.rmempty = true;
	},

	configSummary: function(section) {
		if (section.enabled != '1')
			return null;

		return section.origin
			? _('enabled, custom origin: %s').format(section.origin)
			: _('enabled');
	}
});
