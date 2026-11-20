import { h, field, select, empty, tlsMessage } from '../dom.js';

const noStable = 'publisher has no stable release';
const rateLimit = 'GitHub release API rate limit reached';
const kernelErrors = new Map([
	['release checksum mismatch', '发行包的大小或 SHA-256 与原仓库记录不符。'],
	['upstream release checksum unavailable', '无法取得原仓库对此版本和架构的 SHA-256。'],
	['release archive incompatible with this router', '此发行包与路由器的 CPU 或 ABI 不兼容。'],
	['release executable failed version validation', '内核未能运行或报告的版本号不符。'],
	['insufficient resources for this storage mode', '当前存储模式所需的可用空间或内存不足。'],
	['release source unreachable', '无法连接下载来源。'],
	['release source temporarily unreachable', '暂时无法连接下载来源，可稍后重试或使用镜像。'],
	[rateLimit, 'GitHub 的发行版本查询已达限额，可稍后重试或上传原始发行包。'],
	['latest stable release unreachable', '无法连接原仓库获取最新稳定版。'],
	[noStable, '原仓库目前只有测试版。点击「查看发行版本」可选择适用于本机的测试版。'],
	['invalid latest stable release identity', '原仓库返回的稳定版信息无法通过校验。'],
	['latest stable release lacks a verified archive for this router', '最新稳定版没有适用于此路由器的可校验发行包。'],
]);
function kernelMessage(message) {
	if (message?.startsWith('release_tls ')) {
		try { return tlsMessage(JSON.parse(message.slice('release_tls '.length))); } catch { /* legacy task */ }
	}
	return kernelErrors.get(message);
}
const stagedReasons = {
	intent_changed: '下载期间服务设置已更改，请确认后再使用此版本。',
	selection_changed: '下载期间已选择其他内核，可手动切换到暂存版本。',
	preflight_failed: '此版本未通过当前配置校验，可先检查对配置的影响。',
};

export function bootstrapState(status) {
	if (status.staged && status.staged !== status.selected) return '已暂存 ' + status.staged;
	if (status.selected || !status.bootstrap) return '';
	switch (status.bootstrap.stage) {
	case 'running': return '正在准备最新稳定版';
	case 'failed': return bootstrapError(status) === noStable ? '暂无稳定版' : '自动准备失败';
	case 'interrupted': return '自动准备已中断';
	default: return '';
	}
}
function needsManualInstall(status) {
	return !status.selected && ['failed', 'interrupted'].includes(status.bootstrap?.stage);
}
function bootstrapError(status) {
	return status.bootstrap?.result?.error || status.bootstrap?.error;
}
function fallbackSource(status) {
	const error = bootstrapError(status);
	if (error === noStable) return 'upstream';
	return error === rateLimit ? 'bundle' : 'mirror';
}
export function kernelSummary(ui, status, updates, setup = false) {
	const label = h('span', {role:'status'});
	const button = ui.button('', () => kernelDialog(ui, status, updates, needsManualInstall(status) ? fallbackSource(status) : 'upstream'), 'ow-link');
	function update(next) {
		status = next;
		const state = bootstrapState(status);
		const staged = status.staged && status.staged !== status.selected;
		const text = (setup ? '' : 'mihomo · ') + ([status.selected, state].filter(Boolean).join(' · ') || '未安装');
		if (label.textContent !== text) label.textContent = text;
		let action = '安装内核 ›';
		if (staged) action = '查看暂存版本 ›';
		else if (needsManualInstall(status) && bootstrapError(status) === noStable) action = '选择测试版 ›';
		else if (needsManualInstall(status)) action = fallbackSource(status) === 'bundle' ? '上传原始发行包 ›' : '镜像或手动安装 ›';
		else if (status.selected) action = '其他版本 ›';
		else if (state) action = '查看进度 ›';
		if (button.textContent !== action) button.textContent = action;
		button.hidden = setup && !needsManualInstall(status) && !staged;
	}
	update(status);
	updates.addEventListener('change', (e) => update(e.detail), { signal: ui.signal });
	return [label, button];
}
export async function kernelDialog(ui, status, updates, source = 'upstream') {
	const body = h('div', { class: 'ow-stack' });
	const d = ui.dialog('mihomo 内核', body);
	d.classList.add('ow-kernel-dialog');
	const tag = h('input', { placeholder: 'v1.19.34', required: true, maxlength: 100, 'aria-label': '版本号' });
	const transport = select(
		'下载来源',
		[
			['upstream', '原仓库 Release'],
			['mirror', 'HTTPS 镜像'],
			['url', '自定义下载地址'],
			['bundle', '上传原始发行包'],
		],
		source,
		reveal,
	);
	const location = h('input', { type: 'url', placeholder: 'https://…' });
	const file = h('input', { type: 'file', accept: '.gz', 'aria-label': '原始内核归档' });
	const address = field('HTTPS 地址', location);
	const upload = field('原始内核归档（.gz 或 .tar.gz）', file);
	const mode = select(
		'存储模式',
		[
			['double', '保留已确认的上一版'],
			['single', '单份内核'],
			['tmp', '内存 /tmp'],
		],
		'double',
	);
	const info = h('div', { 'aria-live': 'polite', class: 'ow-muted' });
	const importArchive = ui.button('改为上传原始发行包', () => {
		transport.value = 'bundle';
		reveal();
		file.focus();
		importArchive.hidden = true;
	}, 'ow-link');
	importArchive.hidden = true;
	const catalog = h('div', { hidden: true });
	let versions = [];
	async function change(action, args, onAccepted) {
		await ui.run('kernel_write', { action, args }, onAccepted);
		const latest = await ui.rpc('kernel_read', { action: 'status' });
		updates.dispatchEvent(new CustomEvent('change', { detail: latest }));
		d.close();
	}
	function reveal() {
		address.hidden = !['mirror', 'url'].includes(transport.value);
		upload.hidden = transport.value !== 'bundle';
		mode.querySelector('[value=tmp]').disabled = transport.value === 'bundle';
		if (mode.value === 'tmp' && transport.value === 'bundle') mode.value = 'double';
	}
	async function installVersion() {
		const version = tag.value.trim();
		if (!/^(?:openweir-)?v\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.+-]+)?$/.test(version)) {
			info.textContent = '请选择列表中的测试版，或输入完整版本号，例如 openweir-v1.0.0。';
			tag.focus();
			return;
		}
		const release = versions.find((item) => item.tag === version);
		if (release && !release.installable) {
			info.textContent = '此 Release 缺少当前架构的可校验发行包。';
			return;
		}
		const args = { tag: version, mode: mode.value };
		let ticket;
		try {
			if (['mirror', 'url'].includes(transport.value)) {
				let url;
				try { url = new URL(location.value); } catch { /* Report the field without echoing its value. */ }
				if (!url || url.protocol !== 'https:' || url.username || url.password)
					throw Error('请填写不含用户名或密码的 HTTPS 地址。');
				args[transport.value] = url.href;
			}
			if (transport.value === 'bundle') {
				const archive = file.files[0];
				if (!archive || !/^[A-Za-z0-9][A-Za-z0-9._+-]*\.gz$/.test(archive.name))
					throw Error('请选择一个保留原始文件名的 .gz 内核归档。');
				const expected = release?.asset;
				if (expected && archive.name !== expected) throw Error('此版本和架构需要 ' + expected);
				ticket = await ui.rpc('kernel_upload', { args: { bytes: archive.size } });
				info.textContent = '正在上传 ' + archive.name;
				await ui.upload(ticket.path + '/' + archive.name, archive);
				args.bundle = ticket.path;
			}
			info.textContent = '正在核对原仓库 SHA-256、架构和内核版本…';
			await change('install-json', args, () => { ticket = null; });
		} catch (error) {
			if (error.name !== 'AbortError') {
				info.textContent = kernelMessage(error.message) || error.message;
				importArchive.hidden = error.message !== rateLimit || transport.value === 'bundle';
			}
		} finally {
			if (ticket) await ui.rpc('kernel_upload', { args: { remove: ticket.id } });
		}
	}
	async function loadVersions() {
		catalog.hidden = false;
		try {
			versions = (await ui.run('kernel_read', { action: 'versions' })) || [];
			if (!versions.length) {
				catalog.replaceChildren(empty('暂无发行版本，可手动填写版本号。'));
				return;
			}
			const options = [
				['', '选择版本'],
				...versions.map((v) => [v.tag, v.tag + (v.prerelease ? ' · 测试版' : ' · 稳定版') +
					(v.installable ? '' : ' · 当前架构无可校验的发行包')]),
			];
			const picker = select('发行版本', options, tag.value, (v) => { tag.value = v; });
			for (let i = 0; i < versions.length; i++) picker.options[i + 1].disabled = !versions[i].installable;
			if (picker.selectedIndex < 0) picker.selectedIndex = 0;
			catalog.replaceChildren(field('发行版本', picker));
		} catch (error) {
			catalog.replaceChildren(empty('读取发行版本失败，可手动填写版本号。' + (kernelMessage(error.message) || error.message)));
			importArchive.hidden = error.message !== rateLimit || transport.value === 'bundle';
		}
	}
	body.addEventListener('input', () => { info.textContent = ''; });
	body.addEventListener('change', () => { info.textContent = ''; });
	tag.addEventListener('input', () => {
		const picker = catalog.querySelector('select');
		if (picker) picker.value = versions.some((v) => v.tag === tag.value) ? tag.value : '';
	});
	const selected = h('strong', {}), active = h('p', { class: 'ow-muted' });
	const pending = h('p', { class: 'ow-muted' }, '候选内核正在等待连续健康检查确认');
	const preparation = h('span', {role:'status'});
	const alternate = ui.button('', () => {
		transport.value = fallbackSource(status);
		reveal();
		if (transport.value === 'upstream') return loadVersions();
		(transport.value === 'bundle' ? file : location).focus();
	}, 'ow-link');
	const bootstrap = h('div', {class:'ow-row'}, preparation, alternate);
	const selectStaged = ui.button('', () => change('select', {tag:status.staged}));
	const rollback = ui.button('', () => change('rollback', {}));
	function update(next) {
		status = next;
		selected.textContent = status.selected || '未选择';
		active.textContent = '已确认版本　' + (status.active || '暂无');
		pending.hidden = !status.pending;
		const state = bootstrapState(status);
		const result = status.bootstrap?.result;
		const reason = status.staged && status.staged === result?.staged ? stagedReasons[result.reason] :
			needsManualInstall(status) && kernelMessage(bootstrapError(status));
		const text = reason ? state + '。' + reason : state;
		if (preparation.textContent !== text) preparation.textContent = text;
		bootstrap.hidden = !state;
		alternate.textContent = fallbackSource(status) === 'upstream' ? '选择测试版' : fallbackSource(status) === 'bundle' ? '上传原始发行包' : '使用 HTTPS 镜像';
		alternate.hidden = !needsManualInstall(status) || source === fallbackSource(status);
		selectStaged.hidden = !status.staged || status.staged === status.selected;
		selectStaged.textContent = '使用已暂存 ' + (status.staged || '');
		rollback.hidden = !status.previous;
		rollback.textContent = '回退 ' + (status.previous || '');
	}
	update(status);
	const changed = (e) => update(e.detail);
	updates.addEventListener('change', changed, {signal:ui.signal});
	d.addEventListener('close', () => updates.removeEventListener('change', changed), {once:true});
	body.append(
		h('p', {}, '已选版本　', selected, '　', status.target || ''),
		active, pending, bootstrap,
		ui.button('查看发行版本', loadVersions),
		catalog,
		field('版本号', tag),
		field('下载来源', transport),
		address,
		upload,
		field('存储模式', mode),
		h('p', { class: 'ow-muted' }, '所有来源均使用原仓库的 SHA-256 校验。'),
		h(
			'div',
			{ class: 'ow-actions' },
			ui.button('验证并安装', installVersion, 'ow-primary'),
			selectStaged, rollback,
		),
		ui.button(
			'检查已安装版本对当前配置的影响',
			async () => {
				try {
					const v = await ui.rpc('kernel_impact', { args: { tag: tag.value || status.staged || status.selected } });
					if (v.unconfigured) {
						info.textContent = '尚未配置主订阅，可先安装内核。';
						return;
					}
					info.replaceChildren(
						h('strong', {}, v.can_compile ? '当前配置已通过检查' : '此版本无法应用当前配置'),
						...(v.issues || []).map((x) => h('p', {}, ui.name(x.object) + ' · ' + x.reason)),
					);
				} catch (error) { info.textContent = error.message; }
			},
			'ow-link',
		),
		info, importArchive,
	);
	reveal();
	if (source === 'upstream' && bootstrapError(status) === noStable) await loadVersions();
	return d;
}
