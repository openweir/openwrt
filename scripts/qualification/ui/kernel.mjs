// Exercise native LuCI upload, ACLs and task polling on a fresh disposable router.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';

const { chromium } = await import(process.env.OPENWEIR_PLAYWRIGHT || 'playwright');
const base = new URL(process.env.OPENWEIR_LUCI_URL);
if (!['localhost', '127.0.0.1', '[::1]'].includes(base.hostname)) throw Error('a local router is required');
const archive = process.env.OPENWEIR_KERNEL_ARCHIVE;
const asset = path.basename(archive);
const match = /^mihomo-(.+)-linux-[A-Za-z0-9_-]+\.tar\.gz$/.exec(asset);
if (!match && !/^mihomo-linux-[a-zA-Z0-9.+-]+\.gz$/.test(asset)) throw Error('an original Linux Release archive is required');
const revision = /-alpha-([0-9a-f]{7,40})\.gz$/.exec(asset)?.[1];
const tag = process.env.OPENWEIR_KERNEL_TAG || (match ? 'v' + match[1] : revision && 'v0.0.0-alpha.' + revision);
if (!tag) throw Error('set OPENWEIR_KERNEL_TAG to the release version');
const password = (await fs.readFile(process.env.OPENWEIR_LUCI_PASSWORD_FILE, 'utf8')).trim();
const output = process.env.OPENWEIR_UI_OUTPUT || 'build/ui-check';
await fs.mkdir(output, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.OPENWEIR_CHROME || undefined });

try {
	const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, locale: 'zh-CN' });
	const errors = [];
	let onLoginPage = true;
	page.on('pageerror', e => {
		// LuCI's login page may attempt its own anonymous UCI lookup.
		if (onLoginPage && e.message.startsWith('RPC call to uci/get failed with error -32002: Access denied')) return;
		errors.push(e.message);
	});
	page.setDefaultTimeout(25000);
	await page.goto(base.href);
	await page.locator('[name=luci_username]').fill(process.env.OPENWEIR_LUCI_USER || 'preview');
	await page.locator('[name=luci_password]').fill(password);
	onLoginPage = false;
	await page.locator('[name=luci_password]').press('Enter');
	const open = page.getByRole('button', { name: '其他版本 ›' });
	await open.click();
	const serviceStatus = () => page.evaluate(async () => {
		const rpc = await L.require('rpc');
		return rpc.declare({ object: 'openweir', method: 'status', reject: true })();
	});
	assert.equal((await serviceStatus()).saved.enabled, false, 'a stopped disposable router is required');
	const dialog = page.getByRole('dialog', { name: 'mihomo 内核' });
	await dialog.getByText('未选择', { exact: true }).waitFor();
	await dialog.getByRole('textbox', { name: '版本号' }).fill(tag);
	await dialog.getByRole('combobox', { name: '下载来源' }).selectOption('bundle');
	const file = dialog.getByLabel('原始内核归档', { exact: true });
	const install = dialog.getByRole('button', { name: '验证并安装' });
	await file.setInputFiles({ name: asset, mimeType: 'application/gzip', buffer: Buffer.from('damaged archive') });
	await install.click();
	await dialog.getByText('发行包的大小或 SHA-256 与原仓库记录不符。', { exact: true }).waitFor();
	assert.equal(await install.isEnabled(), true);
	await page.screenshot({ path: path.join(output, 'luci-kernel-rejected-1280.png') });
	await file.setInputFiles(archive);
	await install.click();
	await dialog.waitFor({ state: 'detached', timeout: 120000 });
	await open.click();
	await dialog.getByText(tag, { exact: true }).waitFor();
	await dialog.getByText(/已确认版本\s+暂无/).waitFor();
	await dialog.getByRole('button', { name: '检查已安装版本对当前配置的影响' }).click();
	await dialog.getByText('尚未配置主订阅，可先安装内核。', { exact: true }).waitFor();
	for (const [width, height] of [[1280, 900], [390, 844]]) {
		await page.setViewportSize({ width, height });
		assert.equal(await dialog.evaluate(el => el.scrollWidth > el.clientWidth + 1), false);
		const bounds = await dialog.boundingBox();
		assert.ok(Math.abs(bounds.x + bounds.width / 2 - width / 2) < 2);
		assert.ok(Math.abs(bounds.y + bounds.height / 2 - height / 2) < 2);
		assert.equal(await page.locator('.error500').count(), 0);
		await page.screenshot({ path: path.join(output, 'luci-kernel-installed-' + width + '.png') });
	}
	assert.equal((await serviceStatus()).saved.enabled, false);
	assert.deepEqual(errors, []);
	console.log('Native LuCI rejected a damaged archive, installed the original and kept the service stopped. Desktop and mobile views passed.');
} finally {
	await browser.close();
}
