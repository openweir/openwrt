export function h(tag, attributes = {}, ...children) {
	const el = document.createElement(tag);
	for (const [key, value] of Object.entries(attributes || {})) {
		if (value == null || value === false) continue;
		if (key.startsWith('on') && typeof value === 'function')
			el.addEventListener(key.slice(2).toLowerCase(), value);
		else if (key === 'class' || key === 'className') el.className = value;
		else if (key === 'style' && typeof value === 'object') Object.assign(el.style, value);
		else el.setAttribute(key, value === true ? '' : String(value));
	}
	for (const child of children.flat(Infinity)) {
		if (child != null && child !== false)
			el.append(child instanceof Node ? child : document.createTextNode(String(child)));
	}
	return el;
}
export function card(title, ...children) {
	return h('section', { class: 'ow-card' }, title && h('h2', {}, title), ...children);
}
export function field(label, input) {
	return h(
		input.matches('input,select,textarea') ? 'label' : 'div',
		{ class: 'ow-field' },
		h('span', {}, label),
		input,
	);
}
export function select(label, options, value, change) {
	const el = h(
		'select',
		{ 'aria-label': label },
		options.map(([id, text]) => h('option', { value: id }, text)),
	);
	el.value = value ?? '';
	if (change) el.addEventListener('change', () => change(el.value));
	return el;
}
export const segment = (ui, label, options, value, change) =>
	h(
		'div',
		{ class: 'ow-segment', role: 'group', 'aria-label': label },
		options.map(([id, text]) => {
			const b = ui.button(text, () => change(id));
			b.setAttribute('aria-pressed', String(id === value));
			return b;
		}),
	);
export const empty = (text) => h('p', { class: 'ow-empty' }, text);
export function bytes(n) {
	if (n == null || !Number.isFinite(n)) return '—';
	const units = ['B', 'KB', 'MB', 'GB', 'TB'];
	let i = 0;
	while (n >= 1000 && i < units.length - 1) {
		n /= 1000;
		i++;
	}
	return n.toLocaleString(undefined, { maximumFractionDigits: i ? 1 : 0 }) + ' ' + units[i];
}
export function clock(t) {
	if (!t) return '—';
	const d = new Date(t < 1e11 ? t * 1000 : t);
	return Number.isNaN(d.getTime()) ? '—' : d.toLocaleTimeString([], { hour12: false });
}
export function download(name, value) {
	const url = URL.createObjectURL(new Blob([value], { type: 'application/json;charset=utf-8' }));
	const link = h('a', { href: url, download: name });
	link.click();
	setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export const modeNames = [
	['smart', '智能'],
	['global', '全局'],
	['direct', '直连'],
];
export const knownNames = {
	'@global': '全局',
	'@direct': 'DIRECT',
	'@reject': 'REJECT',
	'@default': '默认代理',
};
export const resultName = { routed: '已分流', established: '已建立', failed: '失败', closed: '已关闭' };
export async function pages(ui, source, action) {
	const items = [];
	if (!source) return items;
	for (let offset = 0; ; offset += 256) {
		if (ui.signal?.aborted) throw new DOMException('页面已切换', 'AbortError');
		const { data } = await ui.rpc('subscription_read', { action, args: { source, offset, limit: 256 } });
		items.push(...data.items);
		if (items.length >= data.total || data.items.length < 256) return items;
	}
}

const diagnosticText = {
    starting: '正在启动代理',
    releasing: '正在清理接管规则',
    fail_open: '局域网已回退直连',
    protected: '故障保护已生效',
    release_failed: '网络恢复未完成',
    running: '代理已启动',
    mode: '切换代理模式',
    start: '请求启动代理',
    stop: '手动停止代理',
    network_unreachable: '内核发起连接时，系统报告网络不可达',
    connection_refused: '目标端拒绝了连接',
    dns_name_not_found: 'DNS 查询未找到域名',
    tls_certificate_error: 'TLS 证书校验失败',
    io_timeout: '连接读写超时',
    deadline_exceeded: '操作超过时限',
    core_diagnostic: '内核返回了未分类的诊断信息',
    listen_address_in_use: '内核监听地址已被占用',
    disk_full: '可写存储空间已满',
    permission_denied: '内核报告权限不足，日志未指明具体资源',
    core_rule_watch_permission: '内核无法监听规则集目录的文件变更，当前已载入的规则仍可使用',
    core_rule_file_permission: '内核没有权限读取分流规则文件',
    core_config_file_permission: '内核没有权限读取启动配置文件',
    core_work_file_permission: '内核没有权限访问工作目录中的文件',
    core_tun_device_permission: '内核没有权限打开 /dev/net/tun',
    core_tproxy_socket_permission: '内核没有权限设置透明代理套接字',
    core_icmp_socket_permission: '内核没有权限使用 ICMP 套接字',
    core_listener_permission: '内核没有权限绑定监听端口',
    core_route_mark_permission: '内核没有权限设置套接字路由标记',
    core_capability_permission: '进程隔离器无法授予内核所需的权限',
    core_thread_creation_failed: '内核无法创建工作线程',
    handshake_failed: '连接握手失败',
    invalid_configuration: '内核拒绝了配置',
    dns_default_upstream: '已配置默认上游或全域 DNS 规则。请将它改为按域名转发，或关闭 OpenWeir 的 DNS 保护',
    dns_servers_file: 'servers-file 可在运行时更换上游，请检查该文件或关闭 OpenWeir 的 DNS 保护',
    dns_dynamic_config: 'conf-script 动态生成 DNS 配置，无法确认上游。可关闭 OpenWeir 的 DNS 保护',
    dns_no_instance: '找不到为所选局域网接口提供解析的 dnsmasq 实例',
    dns_include_directory: '需要一个由此局域网使用、可加载 .conf 文件的临时 conf-dir',
    dns_shared_instance: '此 dnsmasq 实例同时服务受管与其他网络，请拆分实例或关闭 OpenWeir 的 DNS 保护',
    dns_config_unreadable: '无法读取 dnsmasq 实例及其引用的配置，请检查 conf-file 和 conf-dir',
    dns_file_collision: 'dnsmasq 已有同名上游配置，请检查 99-openweir-upstream.conf 的归属',
    'network apply failed at fault_flow_offload': '防火墙已启用流量分载，现有连接可能绕过故障保护。请关闭防火墙流量分载，或启用故障时回退直连',
    'network apply failed at service_stopping': '正在停止服务，本次接管已取消',
    kernel_validation_timeout: '内核配置校验超时',
    kernel_storage_reserve: '剩余空间不足以保存配置和恢复预留空间',
    kernel_storage_full: '保存内核状态时空间已满',
    kernel_permission_denied: '读取内核或保存配置时权限不足',
    kernel_selection_changed: '内核版本正在切换，请在当前任务完成后重试',
    kernel_integrity_check_failed: '已安装内核的文件大小或 SHA-256 校验失败',
    kernel_config_unreadable: '无法读取生成的配置文件',
    kernel_file_missing: '缺少启动所需的内核或配置文件',
    missing_core_jail: '启动代理需要固件提供 /sbin/ujail。缺少该命令时，请安装 procd-ujail',
    kernel_not_installed: '请先在内核管理中安装并选择一个版本',
    kernel_restore_unavailable: '无法从下载源恢复临时内核',
    kernel_preparation_failed: '内核准备失败，未取得更具体的错误分类',
    'openweir-kernel begin failed': '内核准备启动失败，旧版日志未记录具体原因',
};

export function diagnosticMessage(text) {
    if (!text) return '';
    if (diagnosticText[text]) return diagnosticText[text];
    const dns = /^(dns_[a-z_]+) ([a-zA-Z0-9_-]{1,48})$/.exec(text);
    if (dns && diagnosticText[dns[1]]) return 'dnsmasq 实例 ' + dns[2] + ' · ' + diagnosticText[dns[1]];
    const prefix = /^(releasing|release_failed|protected|fail_open) (.+)$/s.exec(text);
    return prefix ? diagnosticText[prefix[1]] + ' · ' + diagnosticMessage(prefix[2]) : text;
}

export function tlsMessage(detail) {
	const messages = {
		expired: 'HTTPS 证书已过期', not_yet_valid: 'HTTPS 证书尚未生效',
		hostname: 'HTTPS 证书与请求的域名不匹配', untrusted: '路由器不信任 HTTPS 证书的签发机构',
		verification_failed: 'HTTPS 证书未通过校验',
	};
	const message = messages[detail?.reason];
	if (!message || ![detail.checked_at, detail.not_before, detail.not_after].every(value => typeof value === 'string')) return message;
	const stamp = value => value.replace('T', ' ').replace(/(\.\d+)?Z$/, '');
	return message + '。核验时路由器时间 ' + stamp(detail.checked_at) + '，证书有效期 ' +
		stamp(detail.not_before) + ' 至 ' + stamp(detail.not_after) + '（UTC）。请核对系统时间及服务端证书。';
}
