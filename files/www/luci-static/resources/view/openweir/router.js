'use strict';
'require view';
'require rpc';
'require request';

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
		function upload(path, file) {
			var data = new FormData();
			data.append('sessionid', rpc.getSessionID());
			data.append('filename', path);
			data.append('filedata', file);
			return request.post(L.env.cgi_base + '/cgi-upload', data, {timeout:0}).then(function(res) {
				var result = res.json();
				if (!res.ok || !result || result.failure || Number(result.size) !== file.size) {
					if (Array.isArray(result && result.failure) && Number(result.failure[0]) === 28)
						throw new Error('路由器的临时存储空间不足。');
					throw new Error('文件上传失败，请检查路由器的临时存储和 LuCI 上传权限。');
				}
			});
		}
		module.mount(root, call, upload);
		return root;
	},
	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
