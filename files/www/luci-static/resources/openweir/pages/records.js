import { card, h, select, segment, empty, clock, download, resultName, diagnosticMessage, datetime } from '../dom.js';

const levels = { info: '信息', warn: '警告', error: '错误' };
const sources = {
	service: '服务',
	core: '代理内核',
	task: '后台任务',
	subscription: '订阅',
	dns: 'DNS',
	firewall: '防火墙',
	watchdog: '守护进程',
};
const outcome = (v) => (v === 'traffic_observed' ? '已建立' : resultName[v] || v || '—');
export async function records(ui) {
	const logs = ui.page === 'logs',
		title = logs ? '日志' : '连接记录';
	const state = (ui.memory[ui.page] ||= {
		follow: true,
		category: '',
		source: '',
		query: ui.detail || '',
		limit: 40,
		device: '',
		rule: '',
	});
	if (ui.detail && state.detail !== ui.detail) {
		const rule = !logs && ui.detail.startsWith('rule:') ? ui.detail.slice(5) : '';
		state.query = rule ? '' : ui.detail;
		state.rule = rule;
		state.detail = ui.detail;
	}
	const ruleSetOf = (rule) => /^RuleSet,(.+)$/.exec(rule || '')?.[1] || '';
	const ruleLabel = (rule) => {
		if (!rule) return '—';
		const set = ruleSetOf(rule);
		if (set) return '规则集 ' + set;
		const [type, ...payload] = rule.split(',');
		return type === 'Match' ? '兜底' : type + (payload.length ? ' ' + payload.join(',') : '');
	};
	const deviceNames = new Map();
	if (!logs) {
		const [, devices] = await Promise.all([ui.catalog(), ui.rpc('devices').catch(() => ({ items: [] }))]);
		for (const device of devices.items || [])
			for (const address of device.addresses || [])
				if (device.name && device.name !== address) deviceNames.set(address, device.name);
	}
	const deviceLabel = (address) =>
		deviceNames.has(address) ? deviceNames.get(address) + ' · ' + address : address;
	const search = h('input', {
		type: 'search',
		'aria-label': '搜索' + title,
		placeholder: logs ? '筛选消息、来源或任务 ID' : '搜索目标、设备、策略组或节点',
		value: state.query,
	});
	const categories = logs
		? [
				['', '全部'],
				['warn', '警告及以上'],
				['error', '仅错误'],
			]
		: [
				['', '全部'],
				['proxy', '代理'],
				['direct', '直连'],
				['reject', '拦截'],
				['failed', '失败'],
			];
	const category = segment(ui, logs ? '日志级别' : '连接类型', categories, state.category, (value) => {
		state.category = value;
		for (const [i, option] of categories.entries())
			category.children[i].setAttribute('aria-pressed', String(option[0] === value));
		draw();
	});
	const source = select('日志来源', [['', '全部来源'], ...Object.entries(sources)], state.source, (v) => {
		state.source = v;
		draw();
	});
	const device = h('select', { 'aria-label': '设备' });
	device.addEventListener('change', () => {
		state.device = device.value;
		draw();
	});
	const ruleFilter = h('select', { 'aria-label': '命中规则集' });
	ruleFilter.addEventListener('change', () => {
		state.rule = ruleFilter.value;
		draw();
	});
	let requestId = 0;
	const follow = ui.button(
		'实时跟随',
		() => {
			state.follow = !state.follow;
			requestId++;
			follow.setAttribute('aria-pressed', String(state.follow));
			if (state.follow) return update();
		},
		'ow-records-follow',
	);
	follow.setAttribute('aria-pressed', String(state.follow));
	const display = h('div', {}),
		footer = h('div', { class: 'ow-records-foot' });
	let entries = [],
		shown = [];
	const columns = ['时间', '设备', '目标', '策略组', '出口', '命中规则', '结果'];
	const rowValues = (c) => [
		clock(c.created_at),
		deviceLabel(c.device) || '—',
		c.destination || '—',
		c.chain
			?.slice()
			.reverse()
			.filter((x) => x.startsWith('group:') || x.startsWith('local:') || ['@global', '@default'].includes(x))
			.map(ui.name)
			.join(' → ') || '—',
		ui.name(c.outbound),
		ruleLabel(c.rule),
		outcome(c.result),
	];
	function draw() {
		const q = state.query.trim().toLocaleLowerCase();
		shown = entries.filter((v) => {
			if (logs)
				return (
					(!state.category ||
						(state.category === 'warn' ? ['warn', 'error'].includes(v.level) : v.level === state.category)) &&
					(!state.source || v.source === state.source) &&
					(!q || (v.message + ' ' + diagnosticMessage(v.message) + ' ' + v.source + ' ' + (sources[v.source] || '')).toLocaleLowerCase().includes(q))
				);
			const type =
				v.result === 'failed'
					? 'failed'
					: v.outbound === '@direct'
						? 'direct'
						: v.outbound === '@reject'
							? 'reject'
							: 'proxy';
			return (
				(!state.category || state.category === type) &&
				(!state.device || state.device === v.device) &&
				(!state.rule || ruleSetOf(v.rule) === state.rule) &&
				(!q || rowValues(v).join(' ').toLocaleLowerCase().includes(q))
			);
		});
		if (!logs) {
			const values = [...new Set(entries.map((c) => c.device).filter(Boolean))];
			if (state.device && !values.includes(state.device)) values.push(state.device);
			device.replaceChildren(
				h('option', { value: '' }, '全部设备'),
				...values.map((x) => h('option', { value: x }, deviceLabel(x))),
			);
			device.value = state.device;
			const sets = [...new Set(entries.map((c) => ruleSetOf(c.rule)).filter(Boolean))].sort();
			if (state.rule && !sets.includes(state.rule)) sets.unshift(state.rule);
			ruleFilter.replaceChildren(
				h('option', { value: '' }, '全部规则集'),
				...sets.map((x) => h('option', { value: x }, x)),
			);
			ruleFilter.value = state.rule;
		}
		if (!shown.length)
			display.replaceChildren(empty(entries.length || state.serverQuery ? '没有匹配的记录' : '暂无' + title));
		else if (logs)
			display.replaceChildren(
				...shown.slice(0, state.limit).map((v) => {
					const row = h('details', { class: 'ow-log', 'data-level': v.level });
					row.append(
						h(
							'summary',
							{},
							h('time', {}, clock(v.time)),
							h('span', { class: 'ow-level ' + v.level }, levels[v.level] || v.level),
							h('span', {}, diagnosticMessage(v.message) + (v.count > 1 ? ' ×' + v.count : '')),
						),
						h(
							'div',
							{ class: 'ow-muted' },
							(sources[v.source] || v.source) + ' · ' + datetime(v.time) + ' · ' + v.message,
						),
					);
					return row;
				}),
			);
		else
			display.replaceChildren(
				h(
					'table',
					{ class: 'ow-table ow-connections' },
					h(
						'thead',
						{},
						h(
							'tr',
							{},
							columns.map((x) => h('th', { scope: 'col' }, x)),
						),
					),
					h(
						'tbody',
						{},
						shown.slice(0, state.limit).map((c) =>
							h(
								'tr',
								{},
								rowValues(c).map((v, j) =>
									h(
										'td',
										{ 'data-label': columns[j], 'data-result': j === 6 ? c.result : null },
										j === 3 && v !== '—' ? h('strong', {}, v) : v,
										j === 2 && c.network ? h('small', {}, c.network.toUpperCase()) : null,
									),
								),
							),
						),
					),
				),
			);
		footer.replaceChildren(
			shown.length > state.limit
				? ui.button(
						'加载更早记录',
						() => {
							state.limit += 40;
							draw();
						},
						'ow-link',
					)
				: h('small', { class: 'ow-muted' }, shown.length + ' 条记录'),
		);
	}
	async function readRows(query, current = () => true) {
		const rows = [];
		for (let offset = 0; offset < 512 && current(); offset += 100) {
			const data = await ui.rpc(ui.page, {
				offset,
				limit: Math.min(100, 512 - offset),
				...(query ? { query } : {}),
			});
			if (ui.signal.aborted || !current()) return [];
			rows.push(...(data.items || []));
			if ((data.items || []).length < 100) break;
		}
		return rows;
	}
	async function update() {
		const id = ++requestId;
		const rows = await readRows(state.serverQuery, () => id === requestId);
		if (ui.signal.aborted || id !== requestId) return;
		if (JSON.stringify(rows) !== JSON.stringify(entries)) {
			entries = rows;
			draw();
		}
	}
	search.addEventListener('input', () => {
		state.query = search.value;
		state.limit = 40;
		draw();
	});
	const remoteSearch =
		logs &&
		h('input', {
			type: 'search',
			'aria-label': '搜索路由器日志',
			placeholder: '搜索路由器日志',
			value: state.serverQuery || '',
		});
	if (remoteSearch) {
		let timer;
		remoteSearch.addEventListener('input', () => {
			requestId++;
			state.serverQuery = remoteSearch.value.trim();
			state.limit = 40;
			clearTimeout(timer);
			timer = setTimeout(() => update().catch((e) => ui.notify(e.message)), 250);
		});
		ui.signal.addEventListener('abort', () => clearTimeout(timer), { once: true });
	}
	const text = () => JSON.stringify(shown, null, 2);
	const toolbar = h('div', { class: 'ow-toolbar' }, category, logs ? source : [device, ruleFilter], search, remoteSearch);
	const header = h('div', { class: 'ow-records-header' }, h('h2', {}, title), follow);
	if (logs)
		header.append(
			ui.button('导出诊断', async () => {
				const [status, kernel, env, events] = await Promise.all([
					ui.rpc('status'),
					ui.rpc('kernel_read', { action: 'status' }),
					ui.rpc('environment'),
					state.serverQuery ? readRows('') : entries,
				]);
				const report = {
					schema_version: 1,
					exported_at: new Date().toISOString(),
					phase: status.phase,
					mode: status.saved.mode,
					fail_open: status.fail_open,
					core: {
						target: kernel.target,
						active: kernel.active,
						selected: kernel.selected,
						trust_ready: kernel.trust_ready,
					},
					environment: env,
					sources: ui.sources.map((s) => ({
						kind: s.kind,
						ready: s.ready,
						node_count: s.node_count,
						rule_count: s.rule_count,
					})),
					events: events.map(({ time, source, level, message }) => ({ time, source, level, message })),
				};
				download('openweir-diagnostics.json', JSON.stringify(report, null, 2));
			}),
		);
	const actions = h(
		'div',
		{ class: 'ow-actions ow-records-actions' },
		ui.button(
			'复制',
			async () => {
				if (navigator.clipboard?.writeText) {
					await navigator.clipboard.writeText(text());
					return;
				}
				const area = h('textarea', { 'aria-label': '复制筛选结果', readonly: true }, text());
				ui.dialog('复制筛选结果', area);
				area.select();
			},
			'ow-link',
		),
		ui.button('导出筛选结果', () => download('openweir-' + ui.page + '.json', text()), 'ow-link'),
		ui.button(
			'清空',
			() => {
				const d = ui.dialog(
					'清空' + title,
					h(
						'div',
						{ class: 'ow-stack' },
						h('p', {}, '清空此页的所有记录？'),
						ui.button(
							'清空' + title,
							async () => {
								await ui.rpc('clear', { page: ui.page });
								d.close();
								entries = [];
								draw();
								await update();
							},
							'ow-danger',
						),
					),
				);
			},
			'ow-link',
		),
	);
	toolbar.classList.add('ow-records-toolbar');
	toolbar.append(actions);
	draw();
	await update();
	ui.poll(async () => {
		if (state.follow && !display.querySelector('details[open]')) await update();
	});
	return h('div', { class: 'ow-records-page' }, header, card(null, toolbar, display, footer));
}
