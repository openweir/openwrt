// Deterministic rpcd replies for exercising presentation states without a router.
export function fixture(empty = false, preparing = false) {
	const id = (n) => 'node:' + String(n).padStart(32, '0');
	const nodes = ['香港 01', '日本 02', '美国 03', '新加坡 01'].map((name, i) => ({
		name,
		id: id(i + 1),
		protocol: ['snell', 'vless', 'trojan', 'hysteria2'][i],
		tcp_probe: i !== 3,
	}));
	const groups = [
		{ id: 'group:watch', name: '流媒体', kind: 'selector', members: nodes.map((n) => n.id) },
		{ id: 'group:domestic', name: 'Domestic', kind: 'selector', members: ['@direct', nodes[0].id] },
	];
	const sources = ['标准套餐', '外部订阅', '家庭套餐', '备用订阅'].map((name, i) => ({
		source: 'p' + i,
		name: i === 0 ? '示例服务商 · ' + name : name,
		kind: i === 0 ? 'platform' : 'external',
		format: i === 0 ? 'openweir' : 'clash',
		ready: true,
		epoch: 1,
		generation: 1,
		node_count: 4,
		group_count: 2,
		rule_count: 1,
		...(i === 0 ? { notices: [{code:'platform_routing_warnings', at:'1'}], plan: { total: 2e11, upload: 5e9, download: 37e9, expireAt: '2026-12-19' } } : {}),
		...(i === 2 ? { notices: [{code:'mihomo_unsupported_rule_set',at:'Media',resource:'SRS'}] } : {}),
	}));
	Object.assign(sources[3], {
		last_failure: 'subscription_tls_not_yet_valid',
		last_tls: {
			reason: 'not_yet_valid', checked_at: '1970-01-02T00:00:00Z',
			not_before: '2026-01-01T00:00:00Z', not_after: '2027-01-01T00:00:00Z',
		},
	});
	if (empty) sources.length = 0;
	const saved = { revision: 5, mode: 'smart', enabled: !empty, source: empty ? '' : 'p0', policy: {}, choices: {} };
	const kernel = { target: 'arm64', selected: preparing ? '' : 'v0.1.3', trust_ready: false };
	if (preparing) kernel.bootstrap = {id:'initial', action:'kernel/bootstrap', stage:'running'};
	const installs = [], uploads = [];
	const probes = { url: {}, tcp: {} };
	const controls = { holdProbe: false, longRefresh: false, phase: null, loginPlans: 1, failRefresh: false };
	let pendingProbe;
	const refreshTasks = new Set();
	const reads = [];
	let maxRefreshTasks = 0;
	const choices = {},
		tasks = new Map(),
		trace = [];
	let serial = 0,
		logs = [
			{ time: Date.now(), source: 'service', level: 'info', message: 'running' },
			{ time: Date.now(), source: 'watchdog', level: 'warn', message: 'local_core_unavailable' },
			{ time: Date.now(), source: 'core', level: 'error', message: 'network_unreachable', count: 3 },
		],
		connections = [
			{
				id: 'c',
				created_at: Date.now(),
				device: '192.168.1.23',
				destination: 'media.example:443',
				chain: [nodes[0].id, 'group:watch'],
				outbound: nodes[0].id,
				network: 'tcp',
				rule: 'domain_suffix',
				result: 'traffic_observed',
			},
		];
	let prefs = {
		method: 'tproxy',
		dns: true,
		ipv6: false,
		update_hours: 6,
		enabled: false,
		networks: ['lan'],
	};
	const phase = () => controls.phase || (saved.enabled && saved.mode !== 'direct' ? 'running' : 'direct'),
		activeSince = Date.now() - 86400000;
	const job = (result) => {
		const task = 'job-' + ++serial;
		tasks.set(task, { stage: 'done', result });
		return { task };
	};
	async function rpc(m, r = {}) {
		trace.push(m);
		switch (m) {
			case 'status':
				return { saved, phase: phase(), running_since: activeSince };
			case 'subscription_read': {
				const action = r.action;
				reads.push(action);
				if (action === 'list') return { ok: true, data: sources };
				if (action === 'url') return { ok: true, data: { url: 'https://fixture.invalid/current' } };
				if (action === 'set_match') return { ok: true, data: { matched: /stream/i.test(r.args.query) } };
				if (action === 'agents') return { ok: true, data: ['clash', 'sing-box', 'OpenWeir'] };
				if (action === 'profile')
					return {
						ok: true,
						data: {
							source: saved.source,
							format: 'clash',
							nodes,
							groups,
							rules: [],
							local: false,
							final: groups[0].id,
						},
					};
				if (action === 'status') return { ok: true, data: sources.find((s) => s.source === r.args.source) };
                if (action === 'rules') {
                    const tags = ['Streaming', 'Domestic'];
					const items = tags.filter(tag => !r.args.rule_set || tag === r.args.rule_set)
						.map(tag => ({match:{rule_set:tag},rule_set:tag,target:'@direct'}));
					const sets = Object.fromEntries(tags.map(tag => [tag,1]));
					return {ok:true,data:{items,total:items.length,positions:items.map(row => tags.indexOf(row.rule_set)+1),sets,entries:sets,binary:sets}};
				}
				const rows =
					action === 'nodes'
						? nodes
						: action === 'groups'
							? groups
							: [];
				return {
					ok: true,
					data: {
						items: rows.slice(r.args.offset || 0, (r.args.offset || 0) + (r.args.limit || 50)),
						total: rows.length,
					},
				};
			}
			case 'subscription_write':
				if (r.action === 'site') return job({ok:true,data:{name:'本地服务商'}});
				if (r.action === 'login') {
					const plans = Array.from({length:controls.loginPlans}, (_, i) => ({id:i+1, usable:true, planName:'测试套餐 '+(i+1)}));
					const ids = plans.map(p=>'account-plan-'+p.id);
					for(const [i,plan] of plans.entries()) {
						if(!sources.some(s=>s.source===ids[i])) sources.push({source:ids[i],name:plan.planName,kind:'platform',ready:false});
					}
					return job({ok:true,data:{site:{name:'本地服务商'}, plans, sources:ids}});
				}
				if (r.action === 'configure') {
					const { id, kind, name } = r.args.config;
					sources.push({ source: id, kind, name, ready: false });
				}
				if (r.action === 'preferences' && r.args.preferences?.download_choice) {
					controls.downloadChoice = r.args.preferences.download_choice;
					return job({ok:true,data:{}});
				}
				if (r.action === 'refresh') {
					if (controls.downloadOffer) {
						controls.downloadOffer=false;
						const failed=job({});
						const provider={kind:'rule',code:'provider_unreachable',download_group:{
							id:'group:download',name:'下载策略',selected:'node:one',total:2,
							options:[{id:'node:one',name:'自动测试'},{id:'@direct',name:'DIRECT'}],
						}};
						const row = sources.find(s => s.source === r.args.source);
						if(row){row.last_provider=provider;row.last_failure=provider.code;}
						tasks.set(failed.task,{stage:'failed',error:provider.code,result:{ok:false,error:provider.code,provider}});
						return failed;
					}
					if(controls.failRefresh) {
						controls.failRefresh = false;
						const failed = job({});
						tasks.set(failed.task, {stage:'failed',error:'subscription_request_failed'});
						return failed;
					}
					if (controls.partialReview && !r.args.confirm) {
						return job({ok:true,data:{decision:'confirmation_required',retains_routing:true,confirmation_id:'keep-rest',notices:[
							{code:'mihomo_unsupported_rule_set',at:'Streaming',resource:'SRS'},
                            {code:'rule_provider_reference_unavailable',at:'rule 1 · Streaming',dangerous:true},
						]}});
					}
					if (r.args.confirm === 'keep-rest') controls.partialReview = false;
					if (controls.providerFailure) {
						const code = controls.providerFailure;
						controls.providerFailure = false;
						const failed = job({});
						const provider = {code, kind:'rule', file:'geosite-cn.mrs'};
						const row = sources.find(s => s.source === r.args.source);
						if (row) { row.last_provider = provider; row.last_failure = provider.code; }
						tasks.set(failed.task, {stage:'failed', error:provider.code, result:{ok:false,error:provider.code,provider}});
						return failed;
					}
					if (controls.longRefresh) {
						controls.longRefresh = false;
						return job({ ok: true, data: { decision: 'blocked', notices: Array.from({ length: 24 }, (_, i) => ({
							at: '测试节点 ' + (i+1), code: 'unsupported_rule',
						})) } });
					}
					const row = sources.find(s => s.source === r.args.source);
					if (row) {
						row.ready = true;delete row.last_failure;delete row.last_provider;
						if (!saved.source) saved.source = row.source;
						if (row.kind === 'platform') row.notices = [{code:'platform_routing_warnings', at:'STATIC_REJECT=2,NO_GROUP_NODES=3'}];
					}
					const accepted = job({ ok: true, data: { decision: 'ready', node_count: 1, notices:row?.notices } });
					refreshTasks.add(accepted.task);
					maxRefreshTasks = Math.max(maxRefreshTasks, refreshTasks.size);
					return accepted;
				}
				return job({ ok: true, data: {} });
			case 'environment':
				return { firewall4: true, firewall_backend: 'fw4', firewall_engine: 'nftables', firewall_version: '1.1.1', firewall_tproxy: true, firewall_tun: true, free_bytes: 128e6, ...controls.environment };
			case 'network_preferences':
				return prefs;
			case 'save_network':
				prefs = r.args;
				return job({});
			case 'devices':
				return {
					items: [
						{
							mac: '02:00:00:01:00:01',
							name: '客厅电视',
							addresses: ['192.168.1.23'],
							reachability: 'reachable',
						},
						{
							mac: '02:00:00:01:00:02',
							name: '工作电脑',
							addresses: ['192.168.1.31'],
							reachability: 'reachable',
						},
					],
				};
			case 'kernel_read':
				return r.action === 'status' ? kernel : job([
					{ tag: 'v0.1.4', prerelease: false, installable: true, asset: 'mihomo-0.1.4-linux-arm64.tar.gz' },
					{ tag: 'v0.0.0-alpha.2ca4a53', prerelease: true, installable: true, asset: 'mihomo-linux-arm64-alpha-2ca4a53.gz' },
					{ tag: 'v0.1.5-rc1', prerelease: true, installable: false },
				]);
			case 'kernel_upload':
				return r.args.remove ? { removed: true } : { id: 'fixture-upload', path: '/tmp/openweir-upload/fixture-upload' };
			case 'kernel_write':
				if (controls.kernelInstallError) throw Error(controls.kernelInstallError);
				installs.push(r.args);
				kernel.mode = r.args.mode;
				kernel.selected = r.args.tag;
				return job({ selected: kernel.selected });
			case 'conflicts':
				return { resources: [], blocked: false };
			case 'rule_hits':
				return { Streaming: { count: 3, last: Date.now() } };
			case 'routes':
				return {
					items: connections.map((v) => ({
						group: 'group:watch',
						outbound: v.outbound,
						time: v.created_at,
						evidence: v.result,
					})),
				};
			case 'traffic':
				return {
					available: true,
					up_bytes: 7e8,
					down_bytes: 17.9e9,
					up_bytes_per_second: 2.1e6,
					down_bytes_per_second: 38.2e6,
				};
			case 'health_check':
				return job({
					core: { ok: true, delay_ms: 1 },
					dns: { ok: true, delay_ms: 4 },
					baidu: { ok: true, delay_ms: 32 },
					netease: { ok: true, delay_ms: 41 },
					google: { ok: true, delay_ms: 138 },
					youtube: { ok: true, delay_ms: 152 },
					github: { ok: false, delay_ms: 5000 },
				});
			case 'groups':
				return choices;
			case 'latencies':
				return probes[r.method || 'url'];
			case 'test_nodes': {
				if (controls.holdProbe) {
					controls.holdProbe = false;
					pendingProbe = job({}).task;
					tasks.set(pendingProbe, { stage: 'running' });
					return {task: pendingProbe};
				}
				for (const id of r.args.nodes) {
					const node = nodes.find(n => n.id === id);
					if (!node || (r.method === 'tcp' && !node.tcp_probe)) throw Error('Invalid fixture probe target');
					probes[r.method][id] = {node: id, latency: { measured_at: 100, delay_ms: r.method === 'tcp' ? 12 : 87 }};
				}
				return job({});
			}
			case 'cancel_tests':
				if (pendingProbe) {
					tasks.set(pendingProbe, { stage: 'failed', error: 'context canceled' });
					pendingProbe = null;
				}
				return { cancelled: true };
			case 'live_groups':
				return { items: groups.map((g) => ({ tag: g.id, selected: choices[g.id]?.saved || g.members[0] })) };
			case 'select_node':
				choices[r.group] = {
					state: phase() === 'running' ? 'applied' : 'saved',
					saved: r.node,
					applied: phase() === 'running' ? r.node : '',
				};
				break;
			case 'start':
				saved.enabled = true;
				break;
			case 'stop':
				saved.enabled = false;
				break;
			case 'policy':
				saved.policy = r.policy;
				break;
			case 'save_rules':
				saved.policy.rules = r.args;
				break;
			case 'source':
				probes.url = {};
				probes.tcp = {};
				saved.source = r.source;
				break;
			case 'mode':
				saved.mode = r.mode;
				break;
			case 'custom_rules':
				return { items: saved.policy.rules || [] };
			case 'logs':
				return { items: logs };
			case 'connections':
				return { items: connections };
			case 'clear':
				if (r.page === 'logs') logs = [];
				else connections = [];
				return { cleared: true };
			case 'task':
				refreshTasks.delete(r.task);
				return tasks.get(r.task);
			default:
				throw Error('Unexpected fixture operation ' + m);
		}
		return { task: 'intent-' + ++saved.revision, revision: saved.revision };
	}
	return { rpc, saved, kernel, choices, trace, controls, reads, get maxRefreshTasks() { return maxRefreshTasks; }, installs, uploads, upload: async (path, file) => uploads.push({ path, name: file.name, bytes: file.size }) };
}
