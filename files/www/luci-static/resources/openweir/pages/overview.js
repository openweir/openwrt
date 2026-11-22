import { diagnosticMessage, day } from '../dom.js';
import { h, card, bytes, select, field, empty, segment, modeNames, clock, resultName } from '../dom.js';
import { installLatest, kernelMessage, kernelStorage, kernelSummary } from './versions.js';

const states = {
	running: '已连接',
	direct: '未连接',
	initializing: '正在准备',
	starting: '连接中',
	releasing: '断开中',
	release_failed: '正在恢复网络',
	fail_open: '已回退直连',
	protected: '故障保护中',
	state_unavailable: '状态待修复',
};
const phaseDetail = {
	initializing: '正在读取配置',
	starting: '正在启动代理服务',
	releasing: '正在释放网络规则',
	direct: '全屋流量直连',
	fail_open: '代理故障，局域网已恢复直连',
	protected: '代理流量已暂停，等待内核恢复',
	release_failed: '正在检查网络恢复',
};
const svgNS = 'http://www.w3.org/2000/svg';
function shape(tag, attrs) {
	const el = document.createElementNS(svgNS, tag);
	for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
	return el;
}
function chart(samples) {
	const svg = shape('svg', {
		viewBox: '0 0 300 75',
		preserveAspectRatio: 'none',
		role: 'img',
		'aria-label': '近 1 分钟上下行速率',
	});
	svg.append(shape('path', { d: 'M0 38H300 M0 74H300', class: 'ow-gridline' }));
	const end = Date.now(),
		points = samples.filter((s) => end - s.t <= 60000);
	if (!points.length) return svg;
	const max = Math.max(1, ...points.flatMap((s) => [s.down_bytes_per_second, s.up_bytes_per_second]));
	for (const [key, color] of [
		['down_bytes_per_second', 'var(--ow-teal)'],
		['up_bytes_per_second', 'var(--ow-violet)'],
	]) {
		const line = points.map((s) => [Math.max(0, 300 - (end - s.t) / 200), 72 - (s[key] * 66) / max]);
		if (line.length === 1) {
			svg.append(shape('circle', { cx: line[0][0], cy: line[0][1], r: 2, fill: color }));
			continue;
		}
		const d = line.map(([x, y], i) => (i ? 'L' : 'M') + x.toFixed(1) + ' ' + y.toFixed(1)).join(' ');
		if (key === 'down_bytes_per_second')
			svg.append(
				shape('path', {
					d: d + ' L' + line.at(-1)[0] + ' 75 L' + line[0][0] + ' 75 Z',
					fill: 'var(--ow-tint)',
				}),
			);
		svg.append(
			shape('path', {
				d,
				fill: 'none',
				stroke: color,
				'stroke-width': 2,
				'vector-effect': 'non-scaling-stroke',
			}),
		);
	}
	return svg;
}
function uptime(ms) {
	const t = Math.max(0, Math.floor(ms / 1000)),
		pad = (v) => String(v).padStart(2, '0');
	return (
		(t >= 86400 ? Math.floor(t / 86400) + ' 天 ' : '') +
		[Math.floor(t / 3600) % 24, Math.floor(t / 60) % 60, t % 60].map(pad).join(':')
	);
}
const networkRequirements = new Map([
	['unsupported capture method', '当前接管方式不受支持'],
	['both fw3 and fw4 are active', 'fw3 和 fw4 同时运行，请只启用其中一个'],
	['no active fw3 or fw4 firewall', '请先启用 fw3 或 fw4 防火墙'],
	['numeric policy routing and marked route lookup', 'ip 命令需要支持数字路由表和按流量标记查询路由'],
	['procd process isolation', 'procd 无法隔离代理内核进程'],
	['dnsmasq service with configurable upstream', 'dnsmasq 服务需要支持设置上游 DNS'],
	['DNS lookup command', '缺少用于检查 DNS 解析的命令'],
	['JSON inspection of the active fw4 ruleset', '无法以 JSON 格式读取当前 fw4 规则'],
	['fw4 policy marking and destination lookup', 'fw4 无法标记流量或查询目标地址'],
	['fw4 TProxy target', 'fw4 缺少 TProxy 透明代理支持'],
	['fw4 DNS redirection', 'fw4 无法重定向 DNS 请求'],
	['legacy IPv4 rule inspection and restore', '无法读取或恢复传统 iptables 的 IPv4 规则'],
	['legacy IPv6 rule inspection and restore', '无法读取或恢复传统 iptables 的 IPv6 规则'],
	['active fw3 IPv4 chains', 'fw3 的 IPv4 规则链尚未启用'],
	['active fw3 IPv6 chains', 'fw3 的 IPv6 规则链尚未启用'],
	['fw3 IPv4 DNS redirection', 'fw3 无法重定向 IPv4 DNS 请求'],
	['fw3 IPv6 DNS redirection', 'fw3 无法重定向 IPv6 DNS 请求'],
	['fw3 destination address type match', 'fw3 无法匹配目标地址类型'],
	['fw3 TProxy target', 'fw3 缺少 TProxy 透明代理支持'],
	['fw3 filter and policy marking rules', 'fw3 无法过滤或标记流量'],
	['usable /dev/net/tun device', 'TUN 网络设备不可用（/dev/net/tun）'],
]);
function firewallDetails(env) {
	const names = { fw4: 'fw4 / nftables', fw3: 'fw3 / iptables-legacy', ambiguous: '检测到两套防火墙正在运行', unavailable: '未检测到启用的防火墙' };
	const backend = env ? names[env.firewall_backend] || (env.firewall4 ? names.fw4 : names.unavailable) : '暂时无法检查';
	const fields = [['防火墙', [backend, env?.firewall_version].filter(Boolean).join(' · ')]];
	if (env?.firewall_backend === 'fw3' || env?.firewall_backend === 'fw4') {
		for (const [key, name] of [['firewall_tproxy', 'TProxy'], ['firewall_tun', 'TUN']]) {
			if (typeof env[key] === 'boolean') fields.push([name, env[key] ? '可用' : '缺少运行条件']);
		}
	}
	if (env?.dns_issue) fields.push(['DNS 接管', diagnosticMessage(env.dns_issue)]);
	if (env?.network_requirements?.length) {
		fields.push(['需要处理', env.network_requirements.map((item, i) => [i > 0 && h('br'), networkRequirements.get(item) || item])]);
		if (env.firewall_packages?.length) fields.push(['可提供所缺功能的软件包', env.firewall_packages.join('、')]);
	}
	return fields;
}
function environmentRows(fields) {
	return h('div', { class: 'ow-environment' },
		fields.map(([key, value]) => h('div', {}, h('span', {}, key), h('strong', {}, value))));
}
function sourceCard(ui) {
	const current = ui.status.intent.source;
	const sources = [...ui.sources.filter((s) => !s.revoked)].sort(
		(a, b) => Number(b.source === current) - Number(a.source === current),
	);
	const box = card(
		'',
		h(
			'div',
			{ class: 'ow-row' },
			h('h2', {}, '订阅来源'),
			ui.button('管理', () => ui.go('subscriptions'), 'ow-link'),
		),
	);
	box.classList.add('ow-sources');
	function item(s) {
		const active = s.source === current,
			p = s.usage || s.plan;
		const b = ui.button(
			'',
			async () => {
				if (active || !s.ready) ui.go('subscriptions', s.source);
				else {
					await ui.run('source', { source: s.source, revision: ui.status.intent.revision });
					await ui.refresh();
				}
			},
			'ow-source-line' + (active ? ' is-active' : ''),
		);
		b.setAttribute('aria-label', (active ? '管理' : '切换至') + ' ' + (s.name || s.source));
		const tail = h(
			'div',
			{ class: 'ow-source-sub' },
			p?.total > 0
				? h('span', {}, bytes(p.upload + p.download) + ' / ' + bytes(p.total))
				: h('span', {}, (s.node_count || 0) + ' 个节点'),
			p?.expireAt ? h('span', {}, '到期 ' + day(p.expireAt)) : null,
		);
		const content = h(
			'div',
			{ class: 'ow-source-info' },
			h('strong', {}, s.name || s.source),
			p?.total > 0 && h('progress', { max: p.total, value: Math.min(p.total, p.upload + p.download) }),
			tail,
		);
		b.append(
			h('span', { class: 'ow-avatar' }, Array.from(s.name || '订阅')[0]),
			content,
			h('small', {}, active ? '当前订阅' : s.ready ? '切换' : '管理'),
		);
		return b;
	}
	if (sources.length) {
		const primary = sources.find(s => s.source === current);
		const title = primary?.name || '选择订阅';
		const link = ui.button('管理订阅', () => ui.go('subscriptions'), 'ow-link');
		box.append(h('details', { class: 'ow-source-mobile' },
			h('summary', { 'aria-label': '切换订阅' },
				h('span', { class: 'ow-avatar', 'aria-hidden': 'true' }, Array.from(title)[0]),
				h('span', { class: 'ow-source-info' }, h('strong', {}, title), h('small', {}, '切换订阅')),
			),
			h('div', { class: 'ow-stack' }, ...sources.map(item), link),
		));
	}
	if (!sources.length) box.append(empty('尚未添加订阅'));
	if (sources.length) box.append(h('div', { class: 'ow-source-list' }, ...sources.map(item)));
	return box;
}
function deviceCard(ui, devices) {
	const policy = ui.status.intent.policy || {},
		section = card('');
	section.classList.add('ow-devices');
	let filter = 'all';
	const query = h('input', { type: 'search', placeholder: '搜索名称 / IP / MAC', 'aria-label': '搜索设备' }),
		list = h('div', {});
	const online = devices.filter((d) => d.reachability === 'reachable').length;
	const filters = h('div', { class: 'ow-segment', 'aria-label': '设备筛选', role: 'group' });
	function policyOf(d) {
		return policy.devices?.find((r) => r.address.toLowerCase() === d.mac.toLowerCase())?.target || '';
	}
	// Each row shows the effective choice; picking what new devices get anyway drops the override.
	const effective = (d) => policyOf(d) || (policy.default_direct ? '@direct' : '@proxy');
	async function choose(d, target) {
		if (target === (policy.default_direct ? '@direct' : '@proxy')) target = '';
		const all = (policy.devices || []).filter((x) => x.address.toLowerCase() !== d.mac.toLowerCase());
		if (target) all.push({ address: d.mac, target });
		await ui.run('policy', { revision: ui.status.intent.revision, policy: { ...policy, devices: all } });
		await ui.refresh();
	}
	function draw() {
		const q = query.value.toLowerCase(),
			visible = devices.filter((d) => {
				const explicit = policyOf(d),
					direct = explicit === '@direct' || (!explicit && policy.default_direct);
				return (
					(!q || [d.name, d.mac, ...d.addresses].join(' ').toLowerCase().includes(q)) &&
					(filter === 'all' ||
						(filter === 'online' && d.reachability === 'reachable') ||
						(filter === 'direct' && direct) ||
						(filter === 'proxy' && !direct))
				);
			});
		for (const b of filters.children) b.setAttribute('aria-pressed', String(b.dataset.value === filter));
		list.replaceChildren(
			...visible.map((d) =>
				h(
					'div',
					{ class: 'ow-device-row' },
					h('span', { class: 'ow-dot' + (d.reachability === 'reachable' ? ' good' : '') }),
					h(
						'div',
						{ class: 'ow-device-name' },
						h('strong', {}, d.name || d.mac),
						h('small', {}, d.addresses.join(' · ')),
					),
					segment(
						ui,
						'代理方式',
						[
							['@proxy', '代理'],
							['@direct', '直连'],
						],
						effective(d),
						(v) => choose(d, v),
					),
				),
			),
		);
		if (!visible.length) list.append(empty('暂无匹配设备'));
	}
	for (const [id, text] of [
		['all', '全部'],
		['online', '在线'],
		['proxy', '代理'],
		['direct', '直连'],
	]) {
		const b = ui.button(text, () => {
			filter = id;
			draw();
		});
		b.dataset.value = id;
		filters.append(b);
	}
	query.addEventListener('input', draw);
	draw();
	section.append(
		h(
			'div',
			{ class: 'ow-row' },
			h('h2', {}, '设备'),
			h('small', { class: 'ow-muted' }, '在线 ' + online + ' / ' + devices.length),
		),
		h('div', { class: 'ow-toolbar ow-device-toolbar' }, filters, query),
		list,
	);
	return section;
}
export async function overview(ui) {
	const intent = ui.status.intent,
		running = ui.status.phase === 'running';
	const [prefs, devices, initialKernel, conflicts, cat, routes] = await Promise.all([
		ui.rpc('network_preferences'),
		ui.rpc('devices').catch(() => ({unavailable:true,items:[]})),
		ui.kernelStatus(),
		ui.rpc('conflicts').catch(() => ({unavailable:true})),
		ui.catalog(),
		ui.rpc('routes', { limit: 12 }),
	]);
	let kernel = initialKernel, nextKernelPoll = 0;
	const kernelUpdates = new EventTarget();
	kernelUpdates.addEventListener('change', (event) => { kernel = event.detail; }, {signal:ui.signal});
	if (!kernel.selected || kernel.bootstrap?.stage === 'running') ui.poll(async () => {
		if ((kernel.selected && kernel.bootstrap?.stage !== 'running') || Date.now() < nextKernelPoll) return;
		const previous = kernel;
		nextKernelPoll = Date.now() + (kernel.bootstrap?.stage === 'running' ? 3500 : 30000);
		const next = await ui.rpc('kernel_read', { action: 'status' });
		if (!ui.signal.aborted && previous === kernel)
			kernelUpdates.dispatchEvent(new CustomEvent('change', {detail:next}));
	}, 3500);
	const policy = intent.policy || {};
	const saveP = async (changes) => {
		await ui.run('save_network', { args: { ...prefs, ...changes } });
		await ui.refresh();
	};
	const savePolicy = async (changes) => {
		await ui.run('policy', { revision: intent.revision, policy: { ...policy, ...changes } });
		await ui.refresh();
	};
	const header = h('h2', {}, states[ui.status.phase] || ui.status.phase),
		sub = h('span', { class: 'ow-muted' });
	const start = async () => {
		if (intent.enabled) {
			const d = ui.dialog(
				'断开代理',
				h(
					'div',
					{ class: 'ow-stack' },
					h('p', {}, '断开后全屋设备将直连。'),
					ui.button(
						'断开',
						async () => {
							await ui.run('stop', { revision: intent.revision });
							d.close();
							await ui.refresh();
						},
						'ow-danger',
					),
				),
			);
			return;
		}
		if (!cat.primary) {
			ui.go('subscriptions', 'add');
			return;
		}
		if (!kernel.selected) {
			// Connecting needs a kernel: download the newest stable one first.
			try {
				kernel = await installLatest(ui, kernelUpdates);
			} catch (error) {
				if (error.name !== 'AbortError') ui.notify(kernelMessage(error.message));
				return;
			}
		}
		// Show the disconnect (red) control at once, pulsing until the core is up; the refresh
		// confirms it or rolls it back.
		power.classList.add('on', 'starting');
		power.lastChild.textContent = '点按断开';
		try {
			await ui.run('start', { revision: intent.revision });
		} catch (error) {
			power.classList.remove('on', 'starting');
			power.lastChild.textContent = '点按连接';
			throw error;
		}
		await ui.refresh();
	};
	// Whenever the button offers to disconnect it is red; until the core runs it pulses, and the
	// first render after it comes up settles the ring once.
	const starting = intent.enabled && !running;
	const power = ui.button('', start, 'ow-power' + (intent.enabled ? ' on' : '') + (starting ? ' starting' : running && ui.memory.powerStarting ? ' settled' : ''));
	ui.memory.powerStarting = starting;
	const powerLabel = intent.enabled
		? '点按断开'
		: !cat.primary
			? '先添加订阅'
			: !kernel.selected
				? kernel.bootstrap?.stage === 'running' ? '内核准备中' : '先选择内核'
				: '点按连接';
	power.setAttribute('aria-label', powerLabel);
	const icon = shape('svg', { viewBox: '0 0 24 24', width: 38, height: 38, 'aria-hidden': 'true' });
	icon.append(
		shape('path', {
			d: 'M12 3v9M6.6 6.8a7.5 7.5 0 1 0 10.8 0',
			fill: 'none',
			stroke: 'currentColor',
			'stroke-width': 2.3,
			'stroke-linecap': 'round',
		}),
	);
	power.append(icon, h('span', {}, powerLabel));
	let history = (ui.memory.traffic ||= []);
	if (!running || ui.memory.run !== ui.status.running_since) {
		history.length = 0;
		ui.memory.run = ui.status.running_since;
	}
	const graph = h('div', { class: 'ow-chart' }),
		total = h('strong', {}, '—'),
		rate = h('span', {}, '—');
	function traffic(t) {
		if (t?.available) {
			history.push({ ...t, t: Date.now() });
			while (history.length && Date.now() - history[0].t > 60000) history.shift();
		}
		const last = history.at(-1);
		total.textContent = last ? '↓ ' + bytes(last.down_bytes) + '　↑ ' + bytes(last.up_bytes) : '—';
		rate.replaceChildren(
			h('span', {}, '↓ ' + (last ? bytes(last.down_bytes_per_second) + '/s' : '—')),
			h('span', {}, '↑ ' + (last ? bytes(last.up_bytes_per_second) + '/s' : '—')),
		);
		graph.replaceChildren(chart(history));
	}
	function timer(st = ui.status) {
		if (st.phase === 'starting' && st.confirmation_seconds > 0) {
			sub.textContent = '已接管流量，内核健康确认剩余 ' + st.confirmation_seconds + ' 秒';
			return;
		}
		sub.textContent =
			running && ui.status.running_since
				? '已运行 ' + uptime(Date.now() - ui.status.running_since)
				: phaseDetail[ui.status.phase] || '';
	}
	timer();
	traffic(running ? await ui.rpc('traffic').catch(() => null) : null);
	const statusSide = h(
		'div',
		{ class: 'ow-connection' },
		header,
		sub,
		power,
		h('strong', { class: 'ow-plan-label' }, cat.primary?.name || '尚未选择订阅'),
		h('small', { class: 'ow-muted' }, devices.unavailable ? '等待局域网接口' : devices.items.length + ' 台局域网设备'),
		running && ui.status.side_router && h('small', { class: 'ow-muted' }, '旁路由模式：设备的网关和 DNS 都需要指向本机'),
		h(
			'div',
			{ class: 'ow-graph-block' },
			h('div', { class: 'ow-total' }, '本次流量', total),
			graph,
			h('div', { class: 'ow-rate' }, '近 1 分钟', rate),
		),
	);
	const routeBox = h('div', { class: 'ow-routes' });
	function routeRows(rows) {
		routeBox.replaceChildren(
			...rows.map((r) => {
				const cell = h(
					r.group ? 'button' : 'div',
					r.group
						? { type: 'button', class: 'ow-route', onClick: () => ui.go('proxy', r.group) }
						: { class: 'ow-route' },
					h(
						'span',
						{ class: 'ow-route-icon', 'aria-hidden': 'true' },
						r.outbound === '@direct' ? '↗' : r.outbound === '@reject' ? '⊘' : '⇢',
					),
					h(
						'span',
						{},
						h('strong', {}, r.group ? ui.name(r.group) : ui.name(r.outbound)),
						h(
							'small',
							{},
							r.group
								? ui.name(r.outbound)
								: r.evidence === 'traffic_observed'
									? '已建立'
									: resultName[r.evidence] || '已分流',
						),
					),
				);
				cell.title = clock(r.time);
				return cell;
			}),
		);
		if (!rows.length) routeBox.append(empty('暂无实际代理路线'));
	}
	routeRows(routes.items || []);
	const right = h(
		'div',
		{ class: 'ow-route-side' },
		h(
			'div',
			{ class: 'ow-modes' },
			field(
				'代理模式',
				segment(ui, '代理模式', modeNames, intent.mode, async (mode) => {
					await ui.run('mode', { mode, revision: intent.revision });
					await ui.refresh();
				}),
			),
		),
	);
	if (intent.mode === 'global') {
		const groups = await ui.rpc('groups'),
			sel = groups['@global'];
		const nodes = cat.nodes.filter((n) => !n.special && n.availability !== 'unsupported');
		const saved = sel?.saved || nodes[0]?.id;
		const grid = h('div', { class: 'ow-routes ow-global-nodes', role: 'group', 'aria-label': '全局节点' });
		for (const n of nodes) {
			const cell = h(
				'button',
				{ type: 'button', class: 'ow-route', 'aria-pressed': String(n.id === saved) },
				h('span', { class: 'ow-route-icon', 'aria-hidden': 'true' }, '⇢'),
				h(
					'span',
					{},
					h('strong', {}, n.name),
					h(
						'small',
						{},
						n.id === sel?.applied ? '实际出口' : n.id === saved ? '已选择 · 启动后生效' : n.protocol || '',
					),
				),
			);
			cell.addEventListener('click', async () => {
				if (n.id === saved) return;
				try {
					await ui.run('select_node', { source: intent.source, group: '@global', node: n.id });
					await ui.refresh();
				} catch (e) {
					ui.notify(e.message);
				}
			});
			grid.append(cell);
		}
		right.append(
			h(
				'div',
				{ class: 'ow-row' },
				h('h3', {}, '全局节点'),
				ui.button('管理代理', () => ui.go('proxy'), 'ow-link'),
			),
			nodes.length ? grid : empty('当前订阅没有可用节点'),
		);
	} else if (intent.mode === 'direct') {
		right.append(
			h(
				'div',
				{ class: 'ow-row' },
				h('h3', {}, '全屋直连'),
				ui.button('管理代理', () => ui.go('proxy'), 'ow-link'),
			),
		);
	} else
		right.append(
			h(
				'div',
				{ class: 'ow-row' },
				h('h3', {}, '代理路线'),
				h(
					'div',
					{ class: 'ow-actions' },
					ui.button('管理代理', () => ui.go('proxy'), 'ow-link'),
					ui.button('连接记录 ›', () => ui.go('connections'), 'ow-link'),
				),
			),
			routeBox,
		);
	const probes = h('div', { class: 'ow-checks' }),
		check = ui.button(
			'检测',
			async () => {
				const res = await ui.run('health_check', {});
				ui.memory.checks = { since: ui.status.running_since, result: res };
				drawChecks();
			},
			'ow-link',
		);
	function drawChecks() {
		const v =
			ui.memory.checks?.since === ui.status.running_since && running ? ui.memory.checks?.result : null;
		probes.replaceChildren(
			...[
				['core', '核心'],
				['dns', 'DNS'],
				['baidu', '百度'],
				['netease', '网易云'],
				['google', 'Google'],
				['youtube', 'YouTube'],
				['github', 'GitHub'],
			].map(([k, n]) =>
				h(
					'span',
					{},
					h('i', {
						class:
							'ow-dot' + (v?.[k] ? (v[k].ok ? ' good' : ' bad') : k === 'core' && running ? ' good' : ''),
					}),
					n +
						(v?.[k] ? ' ' + (v[k].ok ? v[k].delay_ms + ' ms' : '超时') : k === 'core' && running ? ' 运行中' : ''),
				),
			),
			check,
		);
		check.disabled = !running;
	}
	drawChecks();
	right.append(probes);
	const hero = h('section', { class: 'ow-card ow-hero', 'aria-label': '连接状态' }, statusSide, right);
	function toggle(label, value, fn) {
		const b = ui.button('', () => fn(!value), 'ow-switch');
		b.setAttribute('role', 'switch');
		b.setAttribute('aria-label', label);
		b.setAttribute('aria-checked', String(value));
		return b;
	}
	const proxyPrefs = card(
		'代理',
		h(
			'div',
			{ class: 'ow-row' },
			'新设备默认',
			segment(
				ui,
				'新设备默认',
				[
					['proxy', '代理'],
					['direct', '直连'],
				],
				policy.default_direct ? 'direct' : 'proxy',
				(v) => savePolicy({ default_direct: v === 'direct' }),
			),
		),
		updateRow('大陆 IP 直连', toggle('大陆 IP 直连', !!prefs.bypass_cn, (v) => saveP({ bypass_cn: v })),
			h('small', { class: 'ow-muted' }, '国内 IP 不经内核，更快；全局模式下不生效')),
		h(
			'div',
			{ class: 'ow-row' },
			'开机启动',
			toggle('开机启动', prefs.enabled, (v) => saveP({ enabled: v })),
		),
	);
	const dnsPrefs = card(
		'DNS',
		updateRow('DNS 保护', toggle('DNS 保护', prefs.dns, (v) => saveP({ dns: v })),
			h('small', { class: 'ow-muted' }, '由内核解析，防污染')),
		upstreamRow(ui, '国内域名', '直连解析', 'domestic', prefs.dns_domestic, (v) => saveP({ dns_domestic: v })),
		upstreamRow(ui, '其他域名', '经代理加密解析', 'foreign', prefs.dns_foreign, (v) => saveP({ dns_foreign: v })),
	);
	const failOpen = prefs.fail_open !== false;
	const failOpenLabel = '代理无响应时回退直连';
	const fallback = toggle(failOpenLabel, failOpen, (v) => saveP({ fail_open: v }));
	fallback.setAttribute('aria-describedby', 'ow-fail-open-help');
	// Recommended settings; the LAN networks, start at boot and the update period are kept.
	const restoreDefaults = () => {
		const d = ui.dialog('恢复默认设置', h('div', { class: 'ow-stack' },
			h('p', {}, 'DNS、大陆 IP 直连、故障回退和节点自动切换将恢复为推荐的默认值，代理会重启一次。'),
			h('small', { class: 'ow-muted' }, '订阅、规则、设备设置和管理的局域网不受影响。'),
			h('div', { class: 'ow-row' },
				ui.button('取消', () => d.close()),
				ui.button('恢复默认', async () => {
					try {
						await ui.run('policy', { revision: intent.revision, policy: { ...policy, auto_failover: undefined } });
						await ui.refresh();
						await ui.run('save_network', { args: {
							...prefs, dns: true, fail_open: true, bypass_cn: false,
							dns_domestic: builtinDNS.domestic, dns_foreign: builtinDNS.foreign,
						} });
						await ui.refresh();
						d.close();
						ui.notify('已恢复默认设置');
					} catch (e) {
						ui.notify(e.message);
					}
				}, 'ow-danger')),
		));
	};
	const repair = card(
		'',
		h('div', { class: 'ow-row' }, h('h2', {}, '故障与恢复'), ui.button('恢复默认', restoreDefaults, 'ow-link')),
		h('div', { class: 'ow-row' }, '防火墙', ui.button('检查运行环境', async () => {
			const env = await ui.rpc('environment');
			if (!ui.signal.aborted) ui.dialog('防火墙运行环境', environmentRows(firewallDetails(env)));
		}, 'ow-link')),
		updateRow(failOpenLabel, fallback, h('small', { id: 'ow-fail-open-help', class: 'ow-muted' }, failOpen
			? '连续 3 次检查失败后恢复直连'
			: '内核故障时代理流量中断')),
		updateRow('节点失联时自动切换',
			toggle('节点失联时自动切换', policy.auto_failover !== false, (v) => savePolicy({ auto_failover: v })),
			h('small', { class: 'ow-muted' }, '切到同组可用节点')),
		h(
			'div',
			{ class: 'ow-row' },
			'记录连接',
			toggle('记录连接', policy.record_connections !== false, (v) => savePolicy({ record_connections: v })),
		),
		ui.button('查看日志', () => ui.go('logs'), 'ow-link'),
	);
	const updates = card(
		'更新',
		h(
			'div',
			{ class: 'ow-row' },
			'订阅自动更新',
			toggle('订阅自动更新', prefs.update_hours > 0, (on) =>
				saveP({ update_hours: on ? ui.memory.updateHours || 6 : 0 }).catch((e) => ui.notify(e.message)),
			),
		),
		prefs.update_hours > 0 && updateInterval(ui, prefs.update_hours, saveP),
		updateRow('OpenWeir 插件', ...pluginUpdate(ui)),
		updateRow(...kernelSummary(ui, kernel, kernelUpdates)),
		updateRow('内核存储位置', ...kernelStorage(ui, kernel, kernelUpdates, segment)),
		// The router checks these lists itself once a week; there is nothing to press.
		updateRow('大陆域名与 IP 列表', h('small', { class: 'ow-muted' }, '每周自动更新'),
			h('small', { class: 'ow-muted' }, ui.status.china_lists ? '更新于 ' + day(ui.status.china_lists) : '插件内置版本')),
	);
	const grid = h(
		'div',
		{ class: 'ow-dashboard' },
		hero,
		// Subscriptions share the column beside the hero.
		h('div', { class: 'ow-side-stack' }, sourceCard(ui)),
		devices.unavailable ? card('设备',empty('局域网接口尚未就绪'),ui.button('重新检测',ui.refresh,'ow-link')) : deviceCard(ui, devices.items),
		proxyPrefs,
		dnsPrefs,
		repair,
		updates,
	);
	const content = h('div', { class: 'ow-stack' });
	if (!ui.sources.some((s) => !s.revoked)) {
		const [{ onboarding }, env] = await Promise.all([
			import('./sources.js'), ui.rpc('environment').catch(() => null),
		]);
		const environment = environmentRows([
			['内核', kernelSummary(ui, kernel, kernelUpdates, true)],
			...firewallDetails(env),
			['其他代理插件', conflicts.unavailable ? '暂时无法检查' : conflicts.blocked ? '检测到冲突' : '未检测到'],
			['可用存储', bytes(env?.free_bytes)],
		]);
		const open = () => onboarding(ui, environment, setup);
		const setup = ui.button('打开初始化引导', open, 'ow-primary');
		content.append(h('div', { class: 'ow-row ow-card' }, h('span', {}, '添加第一个订阅，开始配置全屋代理。'), setup));
		const key = 'openweir.setup.seen.' + location.pathname;
		ui.afterRender = () => {
			if (ui.memory.setupSeen) return;
			try { if (sessionStorage.getItem(key)) return; } catch (_) {}
			open();
			ui.memory.setupSeen = true;
			try { sessionStorage.setItem(key, '1'); } catch (_) {}
		};
	}
	if (conflicts.blocked)
		content.append(
			h(
				'section',
				{ class: 'ow-warning' },
				h('strong', {}, '检测到其他服务正在接管流量'),
				h('span', {}, [...new Set((conflicts.resources || []).map((x) => x.name))].join('、')),
				ui.button('查看并处理', () => {
					const d = ui.dialog(
						'接管冲突',
						h(
							'div',
							{ class: 'ow-stack' },
							h('p', {}, '停止所列服务并重新检查残留规则。'),
							...(conflicts.resources || []).map((x) => h('div', {}, x.name + ' · ' + x.kind)),
							ui.button(
								'确认停止并检查',
								async () => {
									await ui.run('confirm_conflicts', { token: conflicts.token });
									d.close();
									await ui.refresh();
								},
								'ow-primary',
							),
						),
					);
				}),
			),
		);
	if (ui.status.error)
		content.append(
			h(
				'div',
				{ class: 'ow-warning', role: 'alert' },
				diagnosticMessage(ui.status.error),
				ui.button('查看日志', () => ui.go('logs'), 'ow-link'),
			),
		);
	content.append(grid);
	ui.poll(async () => {
		const st = await ui.rpc('status');
		if (ui.signal.aborted) return;
		if (st.phase !== ui.status.phase || st.saved.revision !== intent.revision) {
			if (content.closest('.ow')?.querySelector('dialog[open]')) return;
			await ui.refresh();
			return;
		}
		timer(st);
		if (running) {
			const [t, r] = await Promise.all([ui.rpc('traffic'), ui.rpc('routes', { limit: 12 })]);
			if (ui.signal.aborted) return;
			traffic(t);
			routeRows(r.items || []);
		}
	}, 2500);
	return content;
}

// 检查更新, then 更新到 vX only when a newer verified package exists.
// Title with its note underneath on the left, the control on the right, centred on both.
function updateRow(title, action, note) {
	return h('div', { class: 'ow-row' }, h('span', { class: 'ow-label' }, title, note), action);
}
function pluginUpdate(ui) {
	const action = ui.button('检查更新', () => {}, 'ow-link'),
		note = h('small', { class: 'ow-muted', role: 'status' });
	let candidate = '', latest = false;
	const installed = ui.status.version && ui.status.version !== 'dev' ? ui.status.version : '';
	note.textContent = installed ? '当前 v' + installed : '';
	function show(text) {
		action.textContent = text || (candidate ? '更新到 ' + candidate : latest ? '已是最新' : '检查更新');
		action.disabled = !!text || (latest && !candidate);
		action.classList.toggle('ow-primary', !text && !!candidate);
		action.classList.toggle('ow-link', !!text || !candidate);
	}
	action.addEventListener('click', async () => {
		note.textContent = '';
		try {
			if (candidate) {
				show('正在更新…');
				await ui.run('plugin_update', {});
				note.textContent = '已安装 ' + candidate + '，刷新页面后生效';
				candidate = '';
				latest = true;
				return;
			}
			show('正在检查…');
			const info = await ui.run('plugin_check', {});
			candidate = info.available ? info.candidate : '';
			latest = !candidate;
			note.textContent = '当前 v' + info.installed.replace(/^v/, '');
		} catch (error) {
			if (error.name !== 'AbortError') note.textContent = error.message;
		} finally {
			show();
		}
	});
	return [action, note];
}

// Hours between automatic subscription refreshes, typed by the user (1–720).
function updateInterval(ui, hours, saveP) {
	ui.memory.updateHours = hours;
	const input = h('input', {
		type: 'number', min: 1, max: 720, step: 1, inputmode: 'numeric', value: hours,
		'aria-label': '更新间隔（小时）', class: 'ow-hours',
	});
	input.addEventListener('change', async () => {
		const value = Number(input.value);
		if (!Number.isInteger(value) || value < 1 || value > 720) {
			ui.notify('请输入 1 到 720 之间的整数小时');
			input.value = hours;
			return;
		}
		if (value === hours) return;
		try {
			ui.memory.updateHours = value;
			await saveP({ update_hours: value });
		} catch (e) {
			ui.notify(e.message);
			input.value = hours;
		}
	});
	return h('div', { class: 'ow-row' }, '更新间隔', h('span', { class: 'ow-actions' }, '每', input, '小时'));
}

// Upstreams show a short summary; a dialog edits the list and restores the built-in servers.
const presetDNS = {
	domestic: [
		['阿里 DoH', 'https://223.5.5.5/dns-query'], ['阿里 DoH 备用', 'https://223.6.6.6/dns-query'],
		['腾讯 DoH', 'https://120.53.53.53/dns-query'], ['腾讯 DoH 备用', 'https://1.12.12.12/dns-query'],
		['阿里 DoT', 'tls://223.5.5.5'], ['腾讯 DoT', 'tls://1.12.12.12'],
	],
	foreign: [
		['Cloudflare DoH', 'https://1.1.1.1/dns-query'], ['Cloudflare DoH 备用', 'https://1.0.0.1/dns-query'],
		['Google DoH', 'https://8.8.8.8/dns-query'], ['Google DoH 备用', 'https://8.8.4.4/dns-query'],
		['Quad9 DoH', 'https://9.9.9.9/dns-query'], ['Cloudflare DoT', 'tls://1.1.1.1'], ['Google DoT', 'tls://8.8.8.8'],
	],
};
const builtinDNS = {
	domestic: ['https://223.5.5.5/dns-query', 'https://120.53.53.53/dns-query'],
	foreign: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'],
};
function upstreamRow(ui, title, note, kind, list, save) {
	const builtin = builtinDNS[kind];
	const current = list?.length ? list : builtin;
	const host = (v) => v.replace(/^[a-z]+:\/\//, '').replace(/\/.*$/, '');
	const same = current.join(' ') === builtin.join(' ');
	const summary = (same ? '内置 · ' : '') + current.map(host).join('、');
	const open = () => {
		let items = [...current];
		const rows = h('div', { class: 'ow-stack' });
		const presets = h('div', { class: 'ow-dns-presets' });
		const add = (v) => {
			if (!v || items.includes(v)) return false;
			if (items.length >= 4) {
				ui.notify('最多 4 个服务器');
				return false;
			}
			items.push(v);
			render();
			return true;
		};
		const input = h('input', { type: 'text', placeholder: 'https://… 、tls://… 或 IP', 'aria-label': '添加 DNS 服务器', spellcheck: 'false' });
		const render = () => {
			presets.replaceChildren(...presetDNS[kind].map(([name, v]) => {
				const on = items.includes(v);
				const b = ui.button(name, () => {
					if (on) items.splice(items.indexOf(v), 1);
					else if (!add(v)) return;
					render();
				}, on ? 'ow-chip ow-chip-on' : 'ow-chip');
				b.setAttribute('aria-pressed', String(on));
				b.title = v;
				return b;
			}));
			rows.replaceChildren(...items.map((v, i) => h('div', { class: 'ow-row' },
				h('code', { class: 'ow-upstream' }, v),
				ui.button('移除', () => { items.splice(i, 1); render(); }, 'ow-link'))));
		};
		const d = ui.dialog(title + ' DNS', h('div', { class: 'ow-stack' },
			h('small', { class: 'ow-muted' }, '常用服务器'),
			presets,
			h('small', { class: 'ow-muted' }, '已选（按顺序使用）'),
			rows,
			h('div', { class: 'ow-row' }, input, ui.button('添加', () => {
				if (add(input.value.trim())) input.value = '';
			}, 'ow-link')),
			h('div', { class: 'ow-row' },
				ui.button('恢复内置', () => { items = [...builtin]; render(); }, 'ow-link'),
				ui.button('保存', async () => {
					if (!items.length) return ui.notify('至少保留 1 个服务器');
					try {
						await save(items);
						d.close();
					} catch (e) {
						ui.notify(e.message);
					}
				}, 'ow-primary')),
		));
		render();
	};
	return updateRow(title, ui.button('管理', open, 'ow-link'),
		h('small', { class: 'ow-muted' }, note + ' · ' + summary));
}
