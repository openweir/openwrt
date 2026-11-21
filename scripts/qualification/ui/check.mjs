import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url)),
	root = path.resolve(here, '../../..');
const assets = path.resolve(process.env.OPENWEIR_UI_ASSETS || path.join(root, 'files/www/luci-static/resources/openweir'));
await fs.access(path.join(assets, 'app.js'));
const { chromium } = await import(process.env.OPENWEIR_PLAYWRIGHT || 'playwright');
const output = process.env.OPENWEIR_UI_OUTPUT || path.join(root, 'build/ui-check');
await fs.mkdir(output, { recursive: true });
const html =
	'<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OpenWeir · LuCI</title><link rel="stylesheet" href="/style.css"><style>body{margin:0}dialog{margin:0;top:0;left:0}</style><div id="app"></div><script type="module">import {mount} from "/app.js";import {fixture} from "/fixture.js";const qs=new URLSearchParams(location.search);const f=fixture(qs.has("empty"),qs.has("bootstrap"));window.model=f;mount(document.querySelector("#app"),async(m,r)=>structuredClone(await f.rpc(m,r)),f.upload);</script>';
const server = http.createServer(async (req, res) => {
	try {
		let url = new URL(req.url, 'http://127.0.0.1').pathname;
		if (url === '/') {
			res.setHeader('Content-Type', 'text/html;charset=utf-8');
			res.end(html);
			return;
		}
		if (url === '/favicon.ico') {
			res.writeHead(204);
			res.end();
			return;
		}
		const file = url === '/fixture.js' ? path.join(here, 'fixture.js') : path.resolve(assets, '.' + url);
		if (url !== '/fixture.js' && !file.startsWith(assets + path.sep)) throw Error('path');
		const data = await fs.readFile(file);
		res.setHeader(
			'Content-Type',
			url.endsWith('css') ? 'text/css' : url.endsWith('svg') ? 'image/svg+xml' : 'text/javascript',
		);
		res.end(data);
	} catch {
		res.writeHead(404);
		res.end();
	}
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const browser = await chromium.launch({
	executablePath: process.env.OPENWEIR_CHROME || undefined,
	headless: true,
});
async function centered(dialog, viewport) {
	const box = await dialog.boundingBox();
	assert.ok(box, 'visible modal');
	assert.ok(Math.abs(box.x + box.width / 2 - viewport.width / 2) <= 1, 'horizontal center');
	assert.ok(Math.abs(box.y + box.height / 2 - viewport.height / 2) <= 1, 'vertical center');
	assert.ok(box.height <= viewport.height - 20 && box.width <= viewport.width - 20, 'dialog fits viewport');
}
async function checkAccountSelection(page, base, {existing = false, count = 1, retry = false} = {}) {
	const query = new URLSearchParams({ scenario: 'login-' + [existing, count, retry].join('-') });
	if (!existing) query.set('empty','');
	await page.goto(base + '/?' + query + '#subscriptions');
	await page.getByRole('button', {name:'＋ 添加订阅'}).click();
	const login = page.getByRole('dialog', {name:'添加订阅'});
	await login.getByRole('button', {name:'服务商登录'}).click();
	await login.getByLabel('服务商地址').fill('https://platform.example');
	await login.getByRole('button', {name:'验证服务商'}).click();
	await login.getByLabel('邮箱').fill('qa@example.invalid');
	await login.getByLabel('密码', {exact:true}).fill('fixture');
	await page.evaluate(({count,retry}) => {
		window.model.controls.loginPlans = count;
		window.model.controls.failRefresh = retry;
	}, {count,retry});
	await login.getByRole('button', {name:'登录',exact:true}).click();
	const sourceWrites = () => page.evaluate(() => window.model.trace.filter(m => m === 'source').length);
	if (existing || count > 1) {
		await login.getByRole('heading', {name:'选择套餐'}).waitFor();
		assert.equal(await page.evaluate(() => window.model.saved.source), existing ? 'p0' : '');
		await login.getByRole('button', {name:'使用',exact:true}).last().click();
	} else if (retry) {
		await login.getByText(/更新失败/).waitFor();
		// A different browser chooses a source while this import awaits a retry.
		await page.evaluate(() => {window.model.saved.source = 'newer-source';});
		await login.getByRole('button', {name:'重新下载'}).click();
	}
	await login.waitFor({state:'detached'});
	assert.equal(await page.evaluate(() => window.model.saved.source), retry ? 'newer-source' : 'account-plan-'+count);
	assert.equal(await sourceWrites(), existing || count > 1 ? 1 : 0);
}
async function checkKernelPreparation(browser, base, viewport) {
	const page = await browser.newPage({viewport});
	try {
		await page.clock.install();
		await page.goto(base + '/?empty&bootstrap');
		const setup = page.getByRole('dialog', {name:'启用全屋代理'});
		await setup.getByText('正在下载', {exact:true}).waitFor();
		const link = setup.getByLabel('粘贴订阅链接');
		await link.fill('https://fixture.invalid/unfinished');
		await page.evaluate(() => {
			window.model.saved.revision++;
			Object.assign(window.model.kernel.bootstrap, {stage:'failed', error:'latest stable release unreachable'});
		});
		await page.clock.runFor(4000);
		await setup.getByText('下载失败', {exact:true}).waitFor();
		assert.equal(await link.inputValue(), 'https://fixture.invalid/unfinished');
		assert.ok(await link.evaluate(element => element === document.activeElement));
		// One button downloads the newest stable kernel; no dialog, no choices.
		await page.evaluate(() => { window.model.controls.kernelInstallError = 'GitHub release API rate limit reached'; });
		await setup.getByRole('button', {name:'重新下载'}).click();
		await setup.getByText('GitHub 查询次数已达上限，请稍后重试').waitFor();
		await page.evaluate(() => { window.model.controls.kernelInstallError = ''; });
		await setup.getByRole('button', {name:'重新下载'}).click();
		await setup.getByText('v0.1.4', {exact:true}).waitFor();
		assert.deepEqual(await page.evaluate(() => window.model.installs), [{tag:'v0.1.4', mode:'double'}]);
		assert.equal(await link.inputValue(), 'https://fixture.invalid/unfinished');
		await page.keyboard.press('Escape');
		await page.getByText('内核 · v0.1.4', {exact:true}).waitFor();
		const reads = () => page.evaluate(() => window.model.trace.filter(op => op === 'kernel_read').length);
		await page.clock.runFor(4000); // let the overview finish re-rendering after the setup closes
		const count = await reads();
		await page.clock.runFor(12000);
		assert.equal(await reads(), count, 'installed kernels do not poll the release status');
		await page.goto(base + '/?bootstrap');
		await page.getByText('内核 · 正在下载').waitFor();
		await page.evaluate(() => {
			const kernel = window.model.kernel;
			kernel.staged = 'v0.1.5';
			kernel.bootstrap = {id:'initial', action:'kernel/bootstrap', stage:'done',
				result:{staged:kernel.staged, reason:'preflight_failed'}};
		});
		await page.clock.runFor(4000);
		await page.getByRole('button', {name:'使用 v0.1.5'}).click();
		await page.getByText('内核 · v0.1.5', {exact:true}).waitFor();
	} finally { await page.close(); }
}
// Advance the browser clock through ten minutes of normal overview polling.
// Measuring document and chart bounds catches cumulative layout growth that
// a screenshot taken immediately after mount does not show.
async function checkOverviewPolling(page, base, width) {
	await page.clock.install();
	await page.goto(base);
	await page.getByRole('heading', {name: '已连接', exact: true}).waitFor();
	const metrics = () => page.evaluate(() => ({
		document: document.documentElement.scrollHeight,
		scrollY: window.scrollY,
		hero: document.querySelector('.ow-hero').getBoundingClientRect().height,
		chart: document.querySelector('.ow-chart').getBoundingClientRect().height,
		svgs: document.querySelectorAll('.ow-chart svg').length,
		polls: window.model.trace.filter(x => x === 'traffic').length,
	}));
	await page.clock.runFor(5000);
	await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight / 2));
	const first = await metrics();
	for (let i=0; i<10; i++) {
		await page.clock.runFor(60000);
		const state = await metrics();
		assert.equal(state.document, first.document, 'LuCI document grows across polls');
		assert.equal(state.scrollY, first.scrollY, 'polling moves the scroll position');
		assert.equal(state.hero, first.hero, 'overview changes height across polls');
		assert.equal(state.chart, first.chart, 'traffic chart grows across polls');
		assert.equal(state.svgs, 1, 'traffic chart accumulates SVG elements');
		assert.ok(state.polls >= first.polls + 20 * (i+1), 'live data was actually refreshed');
	}
	for (const [phase, heading] of [['protected', '故障保护中'], ['fail_open', '已回退直连'], ['direct', '未连接'], ['running', '已连接']]) {
		await page.evaluate(phase => { window.model.controls.phase = phase; }, phase);
		await page.clock.runFor(3500);
		await page.getByRole('heading', {name: heading, exact: true}).waitFor();
		assert.equal((await metrics()).hero, first.hero, 'fault and stop states keep the card height');
		if (phase === 'protected') {
			await page.getByText('代理流量已暂停，等待内核恢复').waitFor();
			await page.screenshot({ path: path.join(output, 'fault-protection-' + width + '.png') });
		}
	}
}
try {
	for (const [width, height] of [
		[1280, 900],
		[390, 844],
	]) {
		const page = await browser.newPage({ viewport: { width, height }, colorScheme: 'light' });
		const errors = [];
		page.on('pageerror', (e) => errors.push(e.message));
		page.on('console', (m) => {
			if (['error', 'warning'].includes(m.type())) errors.push(m.text());
		});
		const base = 'http://127.0.0.1:' + server.address().port;
		await page.goto(base + '/?empty');
		assert.equal(new URL(page.url()).origin, base);
		assert.equal(await page.title(), 'OpenWeir · LuCI');
		const setup = page.getByRole('dialog', { name: '启用全屋代理' });
		await setup.waitFor();
		await centered(setup, { width, height });
		await page.screenshot({ path: path.join(output, 'onboarding-' + width + '.png') });
		await page.keyboard.press('Escape');
		await page.locator('dialog[aria-label="启用全屋代理"]').waitFor({ state: 'detached' });
		const reopen = page.getByRole('button', { name: '打开初始化引导' });
		assert.ok(await reopen.evaluate(el => el === document.activeElement));
		await page.reload();
		await reopen.waitFor();
		assert.equal(await page.locator('dialog[open]').count(), 0);
		await reopen.click();
		await setup.getByLabel('选择配置文件').setInputFiles({
			name: 'router-fixture.txt', mimeType: 'text/plain', buffer: Buffer.from('socks5://192.0.2.1:1080#fixture'),
		});
		await setup.waitFor({ state: 'hidden' });
		await page.locator('.ow-plan-label').filter({ hasText: 'router-fixture.txt' }).waitFor();
		assert.equal(await page.evaluate(() => window.model.trace.includes('source')), false, 'first file uses backend default');
		await checkAccountSelection(page, base);
		await checkAccountSelection(page, base, {retry:true});
		await checkAccountSelection(page, base, {count:2});
		await checkAccountSelection(page, base, {existing:true});
		await page.goto(base);
		await page.getByRole('heading', { name: '已连接', exact: true }).waitFor();
		const inspect = page.getByRole('button', { name: '检查运行环境' });
		const firewall = page.getByRole('dialog', { name: '防火墙运行环境' });
		await inspect.click();
		await firewall.waitFor();
		assert.equal(await firewall.getByText('可用', {exact:true}).count(), 2);
		assert.doesNotMatch(await firewall.innerText(), /需要处理|软件包/);
		await page.keyboard.press('Escape');
		await page.evaluate(() => {
			window.model.controls.environment = {
				firewall_tproxy: false,
				dns_issue: 'dns_default_upstream lan',
				network_requirements: ['fw4 TProxy target', 'DNS lookup command', 'numeric policy routing and marked route lookup'],
				firewall_packages: ['kmod-nft-tproxy', 'nslookup', 'ip-tiny / ip-full'],
			};
		});
		await inspect.click();
		await firewall.getByText('需要处理', {exact:true}).waitFor();
		assert.match(await firewall.innerText(), /dnsmasq 实例 lan · 已配置默认上游/);
		assert.match(await firewall.innerText(), /fw4 缺少 TProxy 透明代理支持[\s\S]+缺少用于检查 DNS 解析的命令[\s\S]+按流量标记查询路由[\s\S]+kmod-nft-tproxy、nslookup、ip-tiny \/ ip-full/);
		await page.keyboard.press('Escape');
		await page.evaluate(() => delete window.model.controls.environment);
		assert.equal(await page.locator('dialog[open]').count(), 0);
		await page.getByRole('heading', { name: '已连接', exact: true }).waitFor();
		const fallbackLabel = '代理无响应时回退直连';
		const fallback = page.getByRole('switch', {name: fallbackLabel});
		assert.equal(await fallback.getAttribute('aria-checked'), 'true', 'legacy preferences default to fail-open');
		await fallback.click();
		await page.getByRole('switch', {name: fallbackLabel, checked: false}).waitFor();
		assert.equal((await page.evaluate(() => window.model.rpc('network_preferences'))).fail_open, false);
		await page.getByText('内核故障时代理流量中断').waitFor();
		await page.getByRole('link', {name: '代理', exact: true}).click();
		await page.getByRole('heading', {name: '代理', exact: true}).waitFor();
		await page.getByRole('link', {name: '概览', exact: true}).click();
		await page.getByRole('switch', {name: fallbackLabel, checked: false}).waitFor();
		await fallback.click();
		await page.getByRole('switch', {name: fallbackLabel, checked: true}).waitFor();
		assert.equal((await page.evaluate(() => window.model.rpc('network_preferences'))).fail_open, true);
		const hero = page.locator('.ow-connection'),
			fixed = (await hero.boundingBox()).height;
		await page.screenshot({ path: path.join(output, 'overview-' + width + '.png'), fullPage: true });
		await page.locator('.ow-row', { hasText: '国内域名' }).getByRole('button', { name: '管理' }).click();
		const dnsDialog = page.getByRole('dialog', { name: '国内域名 DNS' });
		await dnsDialog.getByRole('button', { name: '阿里 DoT' }).click();
		assert.equal(await dnsDialog.getByRole('button', { name: '阿里 DoT' }).getAttribute('aria-pressed'), 'true');
		await page.screenshot({ path: path.join(output, 'dns-dialog-' + width + '.png') });
		await dnsDialog.getByRole('button', { name: '关闭' }).click();
		// 检查更新 offers 更新到 vX only when a newer stable kernel exists.
		const kernelRow = page.locator('.ow-row').filter({ hasText: '内核 ·' });
		await kernelRow.getByRole('button', { name: '检查更新' }).click();
		const upgrade = kernelRow.getByRole('button', { name: '更新到 v0.1.4' });
		await upgrade.waitFor();
		await page.screenshot({ path: path.join(output, 'kernel-' + width + '.png') });
		await upgrade.click();
		await kernelRow.getByRole('button', { name: '已是最新' }).waitFor();
		assert.deepEqual(await page.evaluate(() => window.model.installs), [{ tag: 'v0.1.4', mode: 'double' }]);
		const storage = page.getByRole('group', { name: '内核存储位置' });
		await storage.getByRole('button', { name: '内存' }).click();
		await page.waitForFunction(() => window.model.installs.length === 2);
		assert.deepEqual(await page.evaluate(() => window.model.installs[1]), { tag: 'v0.1.4', mode: 'tmp' });
		await storage.getByRole('button', { name: '闪存' }).click();
		await page.waitForFunction(() => window.model.installs.length === 3);
		await page.evaluate(() => window.model.installs.splice(1));
		await page.getByText('内核 · v0.1.4', { exact: false }).first().waitFor();
		await page.getByRole('button', { name: '检测', exact: true }).click();
		await page.getByText('百度 32 ms').waitFor();
		// Automatic subscription refresh: a switch, then the hours the user types.
		const hours = page.getByRole('spinbutton', { name: '更新间隔（小时）' });
		await hours.fill('8');
		await hours.press('Enter');
		await hours.blur();
		await page.waitForFunction(async () => (await window.model.rpc('network_preferences')).update_hours === 8);
		await page.getByRole('switch', { name: '订阅自动更新', checked: true }).click();
		await page.getByRole('switch', { name: '订阅自动更新', checked: false }).waitFor();
		assert.equal(await hours.count(), 0);
		await page.getByRole('switch', { name: '订阅自动更新', checked: false }).click();
		await page.getByRole('spinbutton', { name: '更新间隔（小时）' }).waitFor();
		assert.equal((await page.evaluate(() => window.model.rpc('network_preferences'))).update_hours, 8);
		await hours.fill('6');
		await hours.blur();
		await page.waitForFunction(async () => (await window.model.rpc('network_preferences')).update_hours === 6);
		// The running core supports URL probes. Exercise cancellation before
		// completing another batch on the same screen.
		await page.getByRole('link', { name: '代理', exact: true }).click();
		const runningBatch = page.getByRole('button', { name: '全部测速' });
		await runningBatch.waitFor();
		await page.evaluate(() => { window.model.controls.holdProbe = true; });
		await runningBatch.click();
		await page.getByRole('button', { name: /香港 01/ }).first().getByText('测速中').waitFor();
		await page.locator('.ow-proxy-toolbar').getByRole('button', { name: '取消测速' }).click();
		await page.waitForFunction(() => window.model.trace.includes('cancel_tests'));
		await runningBatch.click();
		await page.getByRole('button', { name: /香港 01/ }).first().getByText('87 ms').waitFor();
		assert.equal(await page.getByText('context canceled', { exact: true }).count(), 0);
		await page.getByRole('link', { name: '概览', exact: true }).click();
		await page.getByRole('button', { name: '点按断开' }).click();
		await page.getByRole('dialog').getByRole('button', { name: '断开', exact: true }).click();
		await page.getByRole('heading', { name: '未连接', exact: true }).waitFor();
		assert.equal((await hero.boundingBox()).height, fixed);
		await page.getByRole('button', { name: '全局', exact: true }).click();
		await page.getByLabel('全局节点').waitFor();
		await page.getByRole('link', { name: '代理', exact: true }).click();
		await page.getByRole('heading', { name: '代理', exact: true }).waitFor();
		assert.equal(await page.locator('.ow-accordion').count(), 0);
		const methods = page.getByRole('group', { name: '测速方式' });
		const batch = page.getByRole('button', { name: '全部测速' });
		assert.equal(await batch.isDisabled(), true, 'URL tests need a running core');
		await methods.getByRole('button', { name: 'TCP' }).click();
		await page.getByRole('button', { name: /新加坡 01/ }).getByText('不支持').waitFor();
		await batch.click();
		await page.getByRole('button', { name: /香港 01/ }).getByText('12 ms').waitFor();
		await methods.getByRole('button', { name: 'URL' }).click();
		assert.equal(await page.getByText('12 ms', { exact: true }).count(), 0);
		await methods.getByRole('button', { name: 'TCP' }).click();
		await page.getByRole('button', { name: /香港 01/ }).getByText('12 ms').waitFor();
		await page.getByRole('button', { name: /日本 02/ }).click();
		await page.waitForFunction(() => window.model.choices['@global']?.saved.endsWith('2'));
		await page.getByRole('link', { name: '概览', exact: true }).click();
		await page.getByRole('button', { name: '智能', exact: true }).click();
		if (width < 650) await page.getByLabel('切换订阅', { exact: true }).click();
		await page.getByRole('button', { name: '切换至 外部订阅' }).click();
		await page.waitForFunction(() => window.model.saved.source === 'p1');
		await page.getByRole('link', { name: '代理', exact: true }).click();
		const search = page.getByRole('searchbox', { name: '搜索节点或策略组' });
		await search.fill('日本');
		await page.locator('details[open]').first().waitFor();
		await search.fill('');
		await page.screenshot({ path: path.join(output, 'proxy-' + width + '.png'), fullPage: true });
		for (const name of ['订阅', '规则', '日志', '连接记录']) {
			await page.getByRole('link', { name, exact: true }).click();
			await page.getByRole('heading', { name: name === '规则' ? '自定义规则' : name, exact: true }).first().waitFor();
			if (name === '订阅') {
				const clockProblem = page.locator('.ow-source-card').filter({hasText:'备用订阅'});
				await clockProblem.getByText(/证书尚未生效.*1970-01-02.*2026-01-01.*2027-01-01.*UTC/).waitFor();
				const savedProblem = page.locator('.ow-source-card').filter({hasText:'家庭套餐'});
				await savedProblem.locator('details summary').filter({hasText:'1 条导入提醒'}).click();
                await savedProblem.locator('details p').filter({hasText:/Media.*SRS.*该规则集无法被内核直接使用/}).waitFor();
                const account = page.locator('.ow-source-card').filter({ hasText: '示例服务商' });
				await account.getByText('1 条导入提醒', {exact:true}).click();
				const aggregate = account.locator('details[open] p');
				await aggregate.getByText(/服务商报告了 1 条模板提醒，仅提供了总数/).waitFor();
				assert.doesNotMatch(await aggregate.innerText(), /^1\s*·/);
				const startReads = await page.evaluate(() => window.model.reads.length);
				await account.getByRole('button', {name:'更新',exact:true}).click();
				await page.waitForFunction(start => window.model.reads.length > start, startReads);
				assert.deepEqual(await page.evaluate(start => window.model.reads.slice(start), startReads), ['status']);
				await account.getByText('5 条导入提醒', {exact:true}).click();
				await account.getByText('策略组已按默认设置固定为拦截（2 条）', {exact:true}).waitFor();
				assert.doesNotMatch(await account.innerText(), /STATIC_REJECT|1\s*·\s*策略组/);
				await account.getByText('策略组没有可用节点，服务商已将出口设为直连（3 条）', {exact:true}).waitFor();
				await page.evaluate(() => {window.model.controls.providerFailure = 'provider_http_404';});
				await account.getByRole('button',{name:'更新',exact:true}).click();
				await account.getByText('更新失败 · 规则提供方 · geosite-cn.mrs · 返回 HTTP 404 · 已保留上次配置', {exact:true}).waitFor();
				await page.getByRole('link',{name:'概览',exact:true}).click();
				await page.getByRole('link',{name:'订阅',exact:true}).click();
				await account.getByText('上次更新失败 · 规则提供方 · geosite-cn.mrs · 返回 HTTP 404 · 已保留上次配置', {exact:true}).waitFor();
				await page.evaluate(() => {window.model.controls.providerFailure = 'invalid_rule_provider';});
				await account.getByRole('button',{name:'更新',exact:true}).click();
				await account.getByText(/更新失败 · 规则提供方 · geosite-cn\.mrs · 规则文件格式无效.*已保留上次配置/).waitFor();
				await page.evaluate(() => { window.model.controls.downloadOffer=true; });
				await account.getByRole('button',{name:'更新',exact:true}).click();
				const failedSourceCard=await account.elementHandle();
				await account.getByRole('button',{name:'选择规则下载出口'}).click();
				const retry=page.getByRole('dialog',{name:'选择规则下载出口'});
				await retry.getByRole('combobox',{name:'规则下载出口'}).selectOption('@direct');
				await retry.getByRole('button',{name:'保存并重试'}).click();
				await page.waitForFunction(()=>window.model.controls.downloadChoice?.member==='@direct');
				await retry.waitFor({state:'detached'});
				await page.waitForFunction(card=>!card.isConnected,failedSourceCard);
				await account.getByRole('button',{name:'更新',exact:true}).waitFor();
				await page.evaluate(() => {window.model.controls.partialReview = true;});
				await account.getByRole('button',{name:'更新',exact:true}).click();
				const partial = page.getByRole('dialog',{name:'确认订阅变更'});
				await partial.getByText(/跳过这些条目，保留其余分流/).waitFor();
				await partial.getByText(/此次变更会跳过拦截规则.*继续匹配其余规则和兜底出口/).waitFor();
				await partial.getByText(/Streaming · SRS.*无法被内核直接使用/).waitFor();
                await partial.getByText(/rule 1 · Streaming.*此拦截规则引用的规则集未载入/).waitFor();
                assert.equal(await partial.getByRole('checkbox').count(), 0);
				await partial.getByRole('button',{name:'保留其余分流并应用'}).click();
				await partial.waitFor({state:'detached'});
				await page.waitForFunction(() => window.model.controls.partialReview === false);

				const all = page.getByRole('button', {name:'全部更新',exact:true});
				const before = await page.evaluate(() => window.model.trace.filter(m => m === 'subscription_write').length);
				await all.click();
				await page.waitForFunction(n => window.model.trace.filter(m => m === 'subscription_write').length === n+4, before);
				await page.waitForFunction(() => document.querySelector('.ow-main[aria-busy=false]') && ![...document.querySelectorAll('button[aria-busy]')].some(el => el.textContent === '全部更新'));
				assert.equal(await page.evaluate(() => window.model.maxRefreshTasks), 2);

				await account.getByText('服务商账户 · OpenWeir YAML · 每 6 小时自动更新', { exact: true }).waitFor();
				await account.getByRole('button', { name: '编辑', exact: true }).click();
				const edit = page.getByRole('dialog', { name: '编辑订阅' });
				assert.equal(await edit.getByRole('combobox', { name: '订阅请求 UA' }).count(), 0);
				await edit.getByRole('button', { name: '保存', exact: true }).click();
				await edit.waitFor({ state: 'hidden' });
				// Signing out sits on the card, outside the editor.
				const leaveAccount = account.getByRole('button', { name: '退出账户' });
				await leaveAccount.focus();
				await page.keyboard.press('Enter');
				const confirm = page.getByRole('dialog', { name: '退出服务商账户' });
				await centered(confirm, { width, height });
				await page.keyboard.press('Escape');
				await confirm.waitFor({ state: 'detached' });
				assert.ok(await leaveAccount.evaluate(el => el === document.activeElement), 'escape returns to the card button');
				await page.evaluate(() => { window.model.controls.longRefresh = true; });
				const external = page.locator('.ow-source-card').filter({ hasText: '外部订阅' });
				await external.getByRole('button', { name: '编辑' }).click();
				// The editor shows the current link; a changed link is verified before it replaces the old one.
				const address = edit.getByLabel('订阅链接');
				assert.equal(await address.inputValue(), 'https://fixture.invalid/current');
				await address.fill('https://fixture.invalid/replacement');
				await edit.getByRole('button', { name: '保存', exact: true }).click();
				const failure = page.getByRole('dialog', { name: '已保留上次配置' });
				await centered(failure, { width, height });
				await failure.getByText('测试节点 24 · 规则无法转换').scrollIntoViewIfNeeded();
				assert.ok(await failure.locator('.ow-modal-body').evaluate(el => el.scrollTop > 0));
				const header = await failure.locator('.ow-modal-head').boundingBox(), frame = await failure.boundingBox();
				assert.ok(Math.abs(header.y - frame.y) <= 2, 'long content keeps dialog controls visible');
				await page.screenshot({path: path.join(output, 'subscription-review-' + width + '.png')});
				await failure.getByRole('button', { name: '关闭' }).click();
				await failure.waitFor({ state: 'detached' });
				await edit.waitFor();
				assert.equal(await address.inputValue(), 'https://fixture.invalid/replacement');
				await page.keyboard.press('Escape');
				await edit.waitFor({state: 'detached'});
				await page.getByRole('button', { name: '＋ 添加订阅' }).click();
				const dialog = page.getByRole('dialog');
				await centered(dialog, { width, height });
				const ua = dialog.getByRole('combobox', { name: '订阅请求 UA' });
				assert.deepEqual(await ua.locator('option').evaluateAll(items => items.map(item => item.value)), [
					'clash', 'sing-box', 'OpenWeir',
				]);
				assert.equal(await ua.inputValue(), 'clash');
				assert.equal(await dialog.getByPlaceholder('留空使用订阅名称或域名').getAttribute('required'), null);
				await page.keyboard.press('Escape');
			}
			if (name === '规则') {
				await page.getByRole('button',{name:'规则集',exact:true}).click();
				const setRow = tag => page.locator('.ow-rule-sets tr').filter({has:page.getByText(tag,{exact:true})});
				await setRow('Streaming').getByText('订阅',{exact:true}).waitFor();
				await setRow('Streaming').getByRole('button',{name:'详情'}).click();
				const detail = page.getByRole('dialog',{name:'Streaming'});
				await detail.getByText('引用此规则集的规则').waitFor();
				await page.keyboard.press('Escape');
				await setRow('Streaming').getByRole('button',{name:'连接记录'}).click();
				assert.equal(await page.getByRole('combobox',{name:'命中规则集'}).inputValue(), 'Streaming');
			}
			if (name === '日志') {
				const row = page.locator('.ow-log').filter({has:page.getByText('内核发起连接时，系统报告网络不可达 ×3', {exact:true})});
				await row.locator('summary').click();
				await row.getByText(/代理内核 · .*network_unreachable/).waitFor();
				const filter = page.getByRole('searchbox', {name:'搜索日志',exact:true});
				for (const query of ['network_unreachable', '网络不可达']) {
					await filter.fill(query);
					assert.equal(await page.locator('.ow-log').count(), 1);
					await row.waitFor();
				}
				await filter.fill('');
			}
			await page.screenshot({ path: path.join(output, name + '-' + width + '.png'), fullPage: true });
			assert.equal(
				await page.evaluate(() => document.documentElement.scrollWidth > innerWidth),
				false,
				'horizontal overflow in ' + name,
			);
		}
		await page.getByRole('button', { name: '清空', exact: true }).click();
		await page.getByRole('dialog').getByRole('button', { name: '清空连接记录', exact: true }).click();
		await page.getByText('暂无连接记录', { exact: true }).waitFor();
		await page.getByRole('link', { name: '日志', exact: true }).focus();
		await page.keyboard.press('Enter');
		await page.getByText('local_core_unavailable', { exact: true }).waitFor();
		await page.goBack();
		await page.getByText('暂无连接记录', { exact: true }).waitFor();
		await page.reload();
		await page.getByRole('heading', { name: '连接记录', exact: true }).waitFor();
		assert.equal(await page.title(), 'OpenWeir · LuCI');
		assert.equal(await page.locator('vite-error-overlay, nextjs-portal, #webpack-dev-server-client-overlay').count(), 0);
		await checkOverviewPolling(page, base, width);
		await checkKernelPreparation(browser, base, {width,height});
		assert.deepEqual(errors, []);
		console.log(
			width + '×' + height + ' six views, fail-open preference and four status transitions, 10 minutes of stable overview polling, dialogs, URL/TCP probes, kernel install and isolated clear passed',
		);
		await page.close();
	}
} finally {
	await browser.close();
	await new Promise((resolve) => server.close(resolve));
}
