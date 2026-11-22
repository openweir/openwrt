'use strict';
'require view';
'require rpc';

return view.extend({
	load: function() {
		return import(L.resource('openweir/app.js'));
	},
	render: function(module) {
		var root = document.createElement('div');
		var declarations = new Map();
		function call(method, data) {
			var names = Object.keys(data).sort();
			var signature = [method].concat(names).join('/');
			if (!declarations.has(signature))
				declarations.set(signature, rpc.declare({ object: 'openweir', method: method, params: names, reject: true }));
			return declarations.get(signature).apply(null, names.map(function(key) { return data[key]; }));
		}
		var sheet = L.resource('openweir/style.css');
		if (!document.querySelector('link[data-openweir]')) {
			var link = document.createElement('link');
			link.rel = 'stylesheet';
			link.href = sheet;
			link.dataset.openweir = '';
			document.head.appendChild(link);
		}
		module.mount(root, call);
		return root;
	},
	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
