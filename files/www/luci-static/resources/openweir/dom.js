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
// Inline feedback: a line under the row or card whose controls it reports on. A ui.button inside
// that scope writes its error there rather than in the alert at the top of the page, and its next
// press clears the line. The line stays in the accessibility tree while empty, so what is written
// into it is announced: politely, or at once (role alert) for a line about blocking errors, which
// the page clears itself when it retries.
const scopes = new WeakMap();
let lines = 0;
export function feedback(scope, assertive = false) {
	const line = h('p', { class: 'ow-feedback', id: 'ow-feedback-' + ++lines, role: assertive ? 'alert' : 'status' });
	return scope ? attach(scope, line) : line;
}
// A redrawn row keeps its line: the new row reports to the same one.
export function attach(scope, line) {
	scopes.set(scope, line);
	return line;
}
export function feedbackFor(el) {
	for (let node = el; node; node = node.parentElement) if (scopes.has(node)) return scopes.get(node);
	return null;
}
// Text, or text and nodes such as a link; the tone is 'error' or 'done'. The control that
// acted is described by the line.
export function say(line, content, { tone = 'error', control } = {}) {
	line.replaceChildren(...[content].flat());
	line.dataset.tone = tone;
	if (!control) return;
	const ids = (control.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean);
	if (!ids.includes(line.id)) control.setAttribute('aria-describedby', [...ids, line.id].join(' '));
}
export function hush(line) {
	if (!line?.firstChild) return;
	line.replaceChildren();
	delete line.dataset.tone;
}
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
    source: '切换订阅',
    policy: '修改代理策略',
    save_rules: '保存分流规则',
    uninstall: '准备卸载',
    node_failover_requested: '当前节点不可用，已请求切换节点',
    firewall_rules_restored: '防火墙重启或其他程序清除了代理规则，已自动恢复',
    conflict_services_stopped: '已停用冲突的代理插件',
    connections_not_reset: '未能断开旧连接，已打开的页面可能仍走原线路，刷新或重开即可',
    kernel_bootstrap_marker_invalid: '首次内核准备标记无效，已忽略',
    kernel_bootstrap_queue_failed: '首次内核准备未能加入任务队列',
    rule_provider_cleanup_failed: '清理未使用的规则集失败',
    // Why an update a refresh downloaded was not applied (task stage held).
    confirmation_required: '订阅有变更待确认，请到订阅页查看并确认',
    update_blocked: '订阅的新版本无法使用，已保留上次配置，可到订阅页查看原因',
    initial_subscription_select_failed: '无法选择初始订阅',
    superseded: '已被更新的任务取代',
    task_journal_write_failed: '任务记录写入失败',
    china_lists_update_failed: '大陆域名与 IP 列表多次更新失败，继续使用现有列表',
    network_unreachable: '内核发起连接时，系统报告网络不可达',
    connection_refused: '目标端拒绝了连接',
    dns_name_not_found: 'DNS 查询未找到域名',
    tls_certificate_error: 'TLS 证书校验失败',
    io_timeout: '连接读写超时',
    deadline_exceeded: '操作超过时限',
    core_diagnostic: '内核报告了一条其他警告（原文可能含地址或域名，未记录）',
    connection_reset: '连接被对端重置',
    connection_closed: '连接被对端提前关闭',
    geodata_unavailable: 'GeoIP / GeoSite 数据读取或下载失败',
    rule_provider_issue: '规则集加载或更新失败',
    node_provider_issue: '节点提供方加载或更新失败',
    node_health_check_failed: '节点健康检查失败',
    sniffer_issue: '域名嗅探出错',
    core_tun_issue: 'TUN 设备或路由设置出错',
    dial_failed: '内核连接目标失败',
    dns_query_failed: 'DNS 查询失败',
    listen_address_in_use: '内核监听地址已被占用',
    disk_full: '可写存储空间已满',
    permission_denied: '内核报告权限不足，展开查看被拒绝的操作',
    core_tproxy_socket_permission: '内核没有权限设置透明代理套接字',
    core_tproxy_udp_reply_permission: '内核没有权限绑定低端口发送 UDP 回包，QUIC 等流量会丢包',
    core_icmp_socket_permission: '内核没有权限使用 ICMP 套接字',
    core_listener_permission: '内核没有权限绑定监听端口',
    core_route_mark_permission: '内核没有权限设置套接字路由标记',
    core_thread_creation_failed: '内核无法创建工作线程',
    core_file_limit_reached: '内核打开的连接和文件数达到上限（too many open files），新连接会失败或被断开',
    core_file_limit_low: '无法把内核的文件描述符上限提高到 1000000，连接较多时可能出现“too many open files”',
    core_outbound_blocked: '内核的出站连接被系统拒绝，常见原因是防火墙拦截了路由器自身发出的流量',
    core_process_lookup_permission: '内核无法读取进程信息，按进程匹配的规则不会生效',
    core_file_permission: '内核没有权限访问某个文件',
    handshake_failed: '连接握手失败',
    invalid_configuration: '内核拒绝了配置',
    dns_default_upstream: '存在 OpenWeir 无法自动接管的默认上游或全域 DNS 规则，通常来自其他插件的配置文件。请将它改为按域名转发，或关闭 OpenWeir 的 DNS 保护',
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
    kernel_not_installed: '请先在内核管理中安装并选择一个版本',
    kernel_restore_unavailable: '无法从下载源恢复临时内核',
    kernel_preparation_failed: '内核准备失败，未取得更具体的错误分类',
    'openweir-kernel begin failed': '内核准备启动失败，旧版日志未记录具体原因',
    // Why a subscription operation failed (openweir-subscription's error codes), on the
    // subscriptions page and in the log.
    subscription_request_failed: '无法连接订阅服务器，请检查网络后重试',
    invalid_response_size: '服务器返回的内容超过大小上限',
    subscription_size_limit: '订阅内容超过大小上限',
    expanded_subscription_limit: '展开引用的节点和规则后，订阅超过大小上限',
    invalid_subscription: '无法解析订阅内容',
    update_failed: '订阅更新失败',
    operation_failed: '订阅操作失败',
    context_deadline_exceeded: '操作超时',
    not_found: '找不到这个订阅',
    not_ready: '订阅尚未就绪，请先更新订阅',
    login_required: '登录已失效，请重新登录服务商账户',
    suspended: '服务商暂停了此订阅，请到服务商处查看',
    platform_account_revoked: '服务商账户已停用',
    subscription_app_disabled: '服务商已停止向此客户端提供订阅，请联系服务商',
    entitlement_check_failed: '无法向服务商确认套餐状态，请稍后重试',
    invalid_plan_list: '服务商返回的套餐列表无效',
    invalid_node_inventory: '服务商返回的节点清单无效',
    invalid_platform_site: '这个地址不是受支持的服务商站点',
    invalid_origin: '服务商站点地址无效',
    invalid_login: '请填写有效的邮箱和密码',
    invalid_login_response: '服务商返回的登录结果无效',
    invalid_login_token: '服务商返回的登录凭据无效',
    verified_login_required: '请先登录服务商账户',
    source_identity_mismatch: '订阅类型或服务商账户与原订阅不一致',
    redirect_refused: '服务器的跳转不符合下载要求，已拒绝',
    authenticated_redirect_refused: '带登录凭据的请求不能跳转到其他站点，已拒绝',
    candidate_validation_failed: '新配置未通过校验，已保留上次配置',
    preflight_revision_missing: '新配置未完成校验，请重试',
    preflight_revision_changed: '校验期间配置已变更，请重试',
    preflight_confirmation_timeout: '确认新配置超时，请重试',
    invalid_candidate: '新配置无效',
    kernel_invalidation_pending: '订阅已撤销，内核尚未停用它的配置，稍后会自动重试',
    invalid_request: '请求无效',
    unknown_method: '不支持的订阅操作',
    invalid_page: '分页参数无效',
    invalid_source: '订阅设置无效',
    invalid_source_kind: '订阅类型无效',
    invalid_source_url: '订阅链接无效，请填写 http 或 https 地址',
    invalid_external_source: '链接订阅的设置无效',
    invalid_file_source: '本地文件订阅的设置无效',
    invalid_platform_source: '服务商订阅的设置无效',
    invalid_template_filter: '模板筛选条件无效',
    source_config_required: '缺少订阅设置',
    source_preferences_required: '缺少要修改的订阅设置',
    external_source_required: '只有链接订阅可以更换链接',
    not_external: '这不是链接订阅',
    invalid_provider_choice: '所选下载线路无效',
    proxy_not_core: '代理端口不属于内核，已停止经由它下载',
    proxy_connect_refused: '内核代理拒绝了下载连接',
    socket_group_unavailable: '无法建立绕过代理的下载连接',
    literal_address_required: '绕过代理下载需要 IP 地址',
    template_rule_set_unavailable: '内置分流规则引用的规则集暂时无法取得',
    template_cache_write_failed: '无法保存内置分流规则的本机副本',
    geodata_download_failed: 'GeoIP / GeoSite 数据下载失败',
    geodata_digest_mismatch: 'GeoIP / GeoSite 数据校验失败',
    invalid_binary_set_config: '规则集设置无效',
    binary_set_digest_mismatch: '规则集文件校验失败',
    invalid_cached_rule_file: '本机缓存的规则集文件无效',
    invalid_rule_set_format: '规则集格式无效',
    invalid_rule_directory: '规则集目录无效',
    invalid_rule_directory_owner: '规则集目录的属主不正确',
    rule_file_size_exceeds_limit: '规则文件超过大小上限',
    invalid_set_query: '请输入域名或 IP 地址',
    snapshot_exceeds_storage_limit: '订阅数据超过存储上限',
    invalid_subscription_storage: '订阅存储目录无效',
    invalid_subscription_state: '订阅状态文件无效',
    invalid_subscription_snapshot: '订阅快照文件无效',
    // Import notices the subscriptions page reads here (noticeRows).
    invalid_endpoint: '节点的地址、端口或名称无效',
    ambiguous_group: '策略组与其他节点或策略组同名，对它的引用无法使用',
    mihomo_unavailable_member: '策略组的部分成员不存在或不可用，已移除',
    invalid_group: '策略组没有可用成员或配置无效，已跳过',
    cyclic_group: '策略组之间形成循环引用',
    unresolved_target: '规则指向的节点或策略组不存在，已跳过这条规则',
    unsupported_group_option: '策略组有路由器无法使用的选项，已忽略',
};

const taskText = {
    'subscription_write/refresh': '更新订阅',
    'kernel/bootstrap': '首次准备内核',
    save_network: '保存网络设置',
    health_check: '连通性检测',
    plugin_check: '检查插件更新',
    plugin_update: '更新插件',
    subscription_write: '订阅',
    kernel_read: '读取内核',
    kernel: '内核',
    configure: '应用配置',
    latency: '节点测速',
};
const taskStep = {
    configure: '修改设置', login: '登录', logout: '退出登录', site: '获取站点信息',
    preferences: '修改偏好', rollback: '回滚', revoke: '撤销授权',
    url: 'URL 测速', tcp: 'TCP 测速', versions: '获取版本列表', 'install-json': '安装', select: '切换版本',
};
const taskStage = { done: '完成', failed: '失败', held: '未应用' };
function taskName(action) {
    if (taskText[action]) return taskText[action];
    const [head, ...tail] = action.split('/');
    const rest = tail.join('/');
    const name = taskStep[rest] || diagnosticText[rest] || rest;
    return taskText[head] ? taskText[head] + (rest ? ' · ' + name : '') : action;
}

export function datetime(t) {
    if (!t) return '—';
    const d = new Date(typeof t === 'number' && t < 1e11 ? t * 1000 : t);
    if (Number.isNaN(d.getTime())) return '—';
    const p = (n) => String(n).padStart(2, '0');
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' +
        p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}
export const day = (t) => datetime(t).slice(0, 10);

const errorText = {
    'active subscription unavailable': '当前订阅不可用',
    'candidate has unavailable source references': '配置引用了不可用的订阅',
    'cannot launch core': '无法启动内核',
    'cannot prepare authorized rule sets': '无法准备规则集文件',
    'capability information does not match selected release': '内核能力信息与所选版本不符',
    'capability revision mismatch': '内核能力信息版本不符',
    'choose at least one LAN network': '请至少选择一个局域网',
    'configuration revision changed': '配置已被其他操作修改，请刷新后重试',
    'control unavailable': '内核控制接口不可用',
    'core credential unavailable': '内核控制凭据不可用',
    'core did not confirm saved group selection': '内核未确认已保存的节点选择',
    'core exited during startup': '内核在启动过程中退出',
    'core group unavailable': '无法读取内核运行用户组 nogroup',
    'core selection unavailable': '无法读取内核的节点选择',
    'could not save network preferences': '无法保存网络设置',
    'verified plugin update failed': '插件更新失败',
    'A package update is already in progress': '已有插件更新正在进行',
    'APK identity does not match release': '下载的 APK 与发布信息不一致',
    'IPK identity does not match release': '下载的 IPK 与发布信息不一致',
    'Cannot compare package versions': '无法比较插件版本',
    'Cannot download a package matching the release digest': '无法下载与发布校验值一致的安装包，请检查网络或下载镜像',
    'Cannot plan the offline APK upgrade': '无法规划 APK 升级，可能缺少依赖',
    'Cannot read the router architecture': '无法读取路由器架构',
    'Cannot verify the official release metadata': '无法验证官方发布信息',
    'Checking plugin updates requires the ucode command': '检查更新需要 ucode 命令',
    'Checking plugin updates requires an HTTPS downloader (uclient-fetch, curl or GNU Wget)': '检查更新需要 HTTPS 下载工具（uclient-fetch、curl 或 GNU Wget）',
    'Installed APK providers changed during preflight': '升级检查期间已安装的组件发生变化，请重试',
    'Insufficient temporary storage for update': '临时空间不足，无法更新',
    'Invalid installed package version': '已安装的插件版本无效',
    'Package manager did not apply the requested version': '包管理器没有安装目标版本',
    'Refusing package downgrade': '不允许降级插件',
    'invalid network preferences': '设置无效',
    'could not verify network prerequisites': '无法确认网络前置条件',
    'default route has no available group': '默认路线没有可用的策略组',
    'invalid control credential': '内核控制凭据无效',
    'invalid core group': '内核运行用户组 nogroup 无效（不能是 root 组）',
    'invalid launch ticket': '内核启动凭证无效',
    'invalid managed LAN': '受管局域网无效',
    'invalid private core work directory': '内核工作目录无效',
    'invalid rule provider digest': '规则集文件校验失败',
    'local core control unavailable': '本地内核控制接口不可用',
    'local core DNS answer unavailable': '内核 DNS 没有应答',
    'local proxy listener unavailable': '内核代理端口不可用',
    'local proxy negotiation failed': '内核代理握手失败',
    'local TUN not ready': 'TUN 设备未就绪',
    'managed LAN has no usable address': '受管局域网没有可用地址',
    'managed LAN interface unavailable': '受管局域网接口不可用',
    'missing control secret': '缺少内核控制密钥',
    'network ownership lost': '网络接管已被其他程序修改',
    'network resource conflict or incomplete inspection': '网络资源冲突，或检查未完成',
    'no authorized primary source': '没有可用的主订阅',
    'no compatible general-purpose nodes on this release': '当前内核版本不支持订阅中的任何节点',
    'no managed LAN': '没有受管局域网',
    'policy exceeds router limits': '代理策略超出路由器限制',
    'previous confirmed kernel available for recovery': '可回退到上一个确认可用的内核',
    'referenced node no longer exists': '所选节点已不存在',
    'referenced primary node no longer exists': '所选主节点已不存在',
    'referenced subscription unavailable': '所选订阅不可用',
    'revoked': '订阅授权已撤销',
    'route check returned an error': '路由检查出错',
    'router intent changed during validation': '校验期间配置已变更',
    'rule provider name collision': '规则集名称冲突',
    'selected release lacks the configured interception method': '所选内核版本不支持当前的接管方式',
    'source has changed': '订阅内容已变更',
    'state not ready': '服务状态尚未就绪',
    'subscription authorization changed': '订阅授权已变更',
    'subscription changed during startup': '启动过程中订阅已变更',
    'transparent listeners not ready': '透明代理端口未就绪',
    'unexpected DNS canary response': 'DNS 探测返回了意外结果',
    'unsafe core work directory': '内核工作目录权限不安全',
    'unsupported core control interface': '不支持的内核控制接口',
    'unsupported network method': '不支持的接管方式',
    'unsupported rule provider format': '不支持的规则集格式',
    'unsupported state schema': '不支持的状态文件版本',
    'unverified network fault disposition': '未确认故障时的网络处理方式',
    'context deadline exceeded': '操作超时',
    'context canceled': '操作已取消',
    'operation already in progress': '已有相同的操作正在进行，请稍后重试',
    'core is not running': '代理未运行',
    'kernel operation failed': '内核操作失败',
    'kernel selection revision changed': '内核版本已被其他操作切换，请刷新后重试',
    'candidate core rejected the configuration': '内核拒绝了此配置',
    'no compatible members on this device': '没有当前内核可用的成员',
    'saved member unavailable on this device': '保存的节点在当前内核中不可用',
};
// Why a referenced node or rule file could not be downloaded (provider_diagnostic.go), after
// the provider's kind and file on the subscriptions page.
export const providerErrors = {
    provider_timeout: '请求超时', provider_dns_failed: '无法解析提供方域名',
    provider_tls_untrusted: 'HTTPS 证书校验失败', provider_connection_refused: '提供方拒绝连接',
    provider_unreachable: '无法连接提供方', private_provider_address: '提供方指向私有或本地地址，已阻止访问',
    provider_redirect_refused: '提供方重定向不符合下载策略', invalid_provider_url: '提供方下载地址无效',
    provider_limit: '引用的提供方数量超过上限', provider_size_limit: '提供方文件超过下载上限', provider_incomplete: '文件传输不完整',
    provider_cancelled: '下载已取消', provider_download_failed: '引用文件下载失败',
    invalid_proxy_provider: '节点文件格式无效', invalid_rule_provider: '规则文件格式无效',
    node_limit: '节点数量超过上限', rule_limit: '规则数量超过上限',
};
// The name of a node or group by its ID, when the page has read the subscription (app.js).
let memberName = () => '';
export function nameMembers(name) {
    memberName = name;
}
// The objects the kernel's rejections name besides a node or group (kernelcli rejection).
const rejectedEntries = { proxy: '某个节点', 'proxy group': '某个策略组', rule: '某条规则', rules: '某条规则' };
// The proxy plugins OpenWeir stops when it starts, by their init script names.
const pluginNames = {
    openclash: 'OpenClash', passwall: 'PassWall', passwall2: 'PassWall 2', homeproxy: 'HomeProxy',
    v2raya: 'v2rayA', shadowsocksr: 'ShadowSocksR Plus+', nikki: 'Nikki', momo: 'Momo',
};
export const pluginName = (id) => pluginNames[id] || id;
const conflictKinds = {
    service: '服务', process: '进程', nft: 'nftables', xtables: 'iptables', route: '策略路由', listener: '端口',
    dnsmasq: 'dnsmasq 配置', interface: '网络接口', autostart: '无法关闭开机自启', unverified: '无法检查',
};
// One thing the conflict scan found holding the network.
export function conflictItem(kind, name) {
    if (kind === 'service' || kind === 'autostart') name = pluginName(name);
    return conflictKinds[kind] ? conflictKinds[kind] + ' ' + name : name;
}
const errorPatterns = [
    [/^local health: (.+)$/s, (m) => '内核健康检查连续失败 · ' + errorMessage(m[1])],
    [/^local control unavailable: (.+)$/s, () => '本地控制接口不可用'],
    [/^(.+) \(release failed: (.+)\)$/s, (m) => errorMessage(m[1]) + ' · 清理接管规则也失败：' + errorMessage(m[2])],
    [/^network takeover blocked by: (.+)$/s, (m) => '仍有无法自动处理的冲突：' + m[1].split('; ').map((item) => {
        const [kind, ...name] = item.split(' ');
        return conflictItem(kind, name.join(' '));
    }).join('、')],
    [/^member unavailable in (.+)$/s, (m) => '策略组 ' + m[1] + ' 中的所选节点不可用'],
    [/^saved member unavailable for (.+)$/s, (m) => '策略组 ' + m[1] + ' 保存的节点不可用'],
    [/^unavailable (?:device|rule) target (.+)$/s, (m) => '规则指向的策略组 ' + m[1] + ' 不可用'],
    [/^unsupported group type (.+)$/s, (m) => '不支持的策略组类型 ' + m[1]],
    // A change the core could not apply in place; it restarts instead.
    [/^reload fallback (.+)$/s, (m) => '无法直接应用更改，已重启内核 · ' + errorMessage(m[1])],
    // What the kernel rejected: a generated node or group, an entry of the configuration or the
    // whole configuration.
    [/^(node|group):([0-9a-f]{32}): (.+)$/s, (m) => {
        const name = memberName(m[1] + ':' + m[2]), node = m[1] === 'node';
        return (name ? (node ? '节点 ' : '策略组 ') + name : node ? '某个节点' : '某个策略组') + ' · ' + errorMessage(m[3]);
    }],
    [/^(configuration|proxy|proxy group|rules?)(?:\[\d+\])?: (.+)$/s, (m) => (rejectedEntries[m[1]] ? rejectedEntries[m[1]] + ' · ' : '') + errorMessage(m[2])],
    [/^candidate core rejected (\S+) configuration$/, (m) => '内核拒绝了 ' + m[1] + ' 配置'],
    [/^subscription_http_([1-5][0-9]{2})$/, (m) => '订阅服务器返回 HTTP ' + m[1]],
    [/^provider_http_([1-5][0-9]{2})$/, (m) => '节点或规则提供方返回 HTTP ' + m[1]],
    [/^(?:subscription|provider)_tls_([a-z_]+)$/, (m) => tlsMessage({ reason: m[1] }) || 'HTTPS 证书校验失败'],
];
function errorMessage(text) {
    if (diagnosticText[text]) return diagnosticText[text];
    if (errorText[text]) return errorText[text];
    if (providerErrors[text]) return providerErrors[text];
    for (const [re, fn] of errorPatterns) {
        const m = re.exec(text);
        if (m) return fn(m);
    }
    const network = /^network (\w+) failed at (\w+)$/.exec(text);
    if (network) return diagnosticText[text] || '网络' + (network[1] === 'apply' ? '接管' : '恢复') + '在 ' + network[2] + ' 步骤失败';
    const wrapped = /^([^:]{1,80}): (.+)$/s.exec(text);
    if (wrapped && (errorText[wrapped[2]] || diagnosticText[wrapped[2]])) return errorMessage(wrapped[2]);
    return text;
}

export function diagnosticMessage(text) {
    if (!text) return '';
    if (diagnosticText[text]) return diagnosticText[text];
    const task = /^(\S+) (done|failed|held) ([A-Za-z0-9_-]+)(?: (.*))?$/s.exec(text);
    if (task) {
        const extra = task[4] && task[4][0] !== '{' ? diagnosticMessage(task[4]) : '';
        return taskName(task[1]) + ' · ' + taskStage[task[2]] + (extra ? ' · ' + extra : '');
    }
    const dns = /^(dns_[a-z_]+) ([a-zA-Z0-9_-]{1,48})$/.exec(text);
    if (dns && diagnosticText[dns[1]]) return 'dnsmasq 实例 ' + dns[2] + ' · ' + diagnosticText[dns[1]];
    const prefix = /^(starting|releasing|release_failed|protected|fail_open|running) (.+)$/s.exec(text);
    return prefix ? diagnosticText[prefix[1]] + ' · ' + diagnosticMessage(prefix[2]) : errorMessage(text);
}

// Log entries whose detail completes the sentence.
const detailSentences = {
    conflict_services_stopped: (d) => diagnosticText.conflict_services_stopped + '：' + d.split(', ').map(pluginName).join('、'),
};
export function eventMessage(v) {
    const sentence = v.detail && detailSentences[v.message];
    return sentence ? sentence(v.detail) : diagnosticMessage(v.message);
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
