import { bytes, tlsMessage } from '../dom.js';
// LuCI loads this module on demand. Subscription secrets are submitted directly
// to rpcd and never enter a route, storage key or display label.
const formats = {
    openweir: 'OpenWeir YAML',
    'sing-box': 'sing-box JSON',
    clash: 'Clash YAML',
    uri: '节点链接',
    surge: 'Surge',
    loon: 'Loon',
    quantumultx: 'Quantumult X',
    shadowrocket: 'Shadowrocket',
};
const kinds = { platform: '服务商账户', file: '本地文件', external: '链接订阅' };
const ids = () =>
    Array.from(crypto.getRandomValues(new Uint8Array(12)), (b) => b.toString(16).padStart(2, '0')).join('');
const actions = (u, ...children) => u.h('div', { class: 'ow-actions' }, ...children);
const muted = (u, text) => u.h('span', { class: 'ow-muted' }, text);
const badge = (u, text) => u.h('span', { class: 'ow-badge' }, text);
const field = (u, title, control) => u.h('label', { class: 'ow-field' }, u.h('span', {}, title), control);
async function write(u, action, args) {
    try {
        return await u.run('subscription_write', { action, args });
    } catch (err) {
        if (action !== 'refresh' && err.tls) throw new Error(tlsMessage(err.tls) || err.message);
        throw err;
    }
}
const input = (u, attrs = {}) => u.h('input', attrs);
const choice = (u, pairs, value, label) => {
    const select = u.h(
        'select',
        { 'aria-label': label },
        ...pairs.map(([v, name]) => u.h('option', { value: v }, name)),
    );
    select.value = value;
    return select;
};
async function read(u, action, args = {}) {
    const result = await u.rpc('subscription_read', { action, args });
    if (result?.ok === false) throw new Error(result.error);
    return result?.data ?? result;
}
const date = (s) =>
    s && Number.isFinite(Date.parse(s))
        ? new Date(s).toLocaleString(undefined, {
              year: 'numeric',
              month: '2-digit',
              day: '2-digit',
              hour: '2-digit',
              minute: '2-digit',
          })
        : '—';
function form(u, controls, submitLabel, handler) {
    const body = u.h('form', { class: 'ow-stack' }, ...controls);
    const submit = u.button(
        submitLabel,
        (event) => {
            event.preventDefault();
            return body.reportValidity() && handler();
        },
        'ow-primary',
    );
    submit.type = 'submit';
    body.append(submit);
    body.addEventListener('submit', (event) => {
        event.preventDefault();
        if (!submit.disabled) submit.click();
    });
    return body;
}
function confirm(u, title, content, label, handler) {
    const body = u.h('div', { class: 'ow-stack' }, content);
    const dialog = u.dialog(title, body);
    let accepted = false;
    const finish = new Promise((resolve) => dialog.addEventListener('close', () => resolve(accepted), { once: true }));
    body.append(
        actions(
            u,
            u.button('取消', () => dialog.close()),
            u.button(
                label,
                async () => {
                    accepted = (await handler()) !== false;
                    dialog.close();
                },
                'ow-danger',
            ),
        ),
    );
    return finish;
}
const notices = {
    mihomo_protocol_unsupported: '当前内核无法使用该协议，请切换到支持它的版本',
    mihomo_capability_unknown: '选择内核后可确认此节点是否可用',
    mihomo_router_field_ignored: '路由器使用自身的监听、安全及网络设置，已忽略模板中的对应选项',
    mihomo_unsupported_rule: '这条规则无法转换为 mihomo 规则',
    mihomo_unsupported_rule_set: '该规则集无法直接用于 mihomo，请提供 YAML、text 或 MRS 格式',
    subconv_unsupported_proxy: '该节点的协议无法转换，已跳过',
    subconv_unsupported_option: '该节点有无法转换的选项，已跳过',
    subconv_unsupported_rule: '这条规则无法转换为 mihomo 规则，已跳过',
    subconv_unsupported_rule_set: '该规则集无法转换为 mihomo 规则集，已跳过',
    subconv_unknown_reference: '引用了不存在的节点或策略组，已跳过',
    subconv_empty_group: '策略组没有可用成员，已跳过',
    subscription_tls_untrusted: '路由器不信任此订阅服务的 HTTPS 证书，请检查固件的 CA 证书和服务商的证书链',
    provider_download_failed: '订阅模板已取得，但其中引用的节点文件或规则集下载失败。请检查路由器到规则提供方的网络，稍后重试',
    superseded: '已有更新的请求接手了此订阅，请查看最新任务的结果',
    subscription_link_unavailable: '服务商未提供可用的套餐订阅链接，或链接暂时无法下载，请稍后重试',
    invalid_plan_detail: '服务商返回的套餐详情不完整或与当前套餐不匹配',
    unavailable_inventory: '模板未导出全部已授权节点',
    local_fallback_removes_rejection: '切换到本地分流会移除原拦截规则',
    unsupported_node: '节点或协议选项无法转换',
    credential_conflict: '节点提供了相互冲突的认证字段',
    invalid_credential: '节点的认证信息无效',
    nonstandard_snell_field: 'Snell 使用 psk，已忽略非标准认证字段',
    nonstandard_snell_credential: 'Snell 缺少标准 psk 认证字段，此节点无法导入',
    provider_required: '订阅引用了尚未载入的节点提供方',
    rule_provider_custom_geo: '订阅使用自定义地理数据库，当前无法还原该条地理规则',
    rule_provider_reference_unavailable: '规则引用的提供方未载入，相关规则无法导入',
    unsupported_rule: '规则无法转换',
    unsupported_group: '策略组无法转换',
    source_mismatch: '来源与当前订阅不一致',
};
function moreRows(u, body, rows, render, noun) {
    let offset = 0;
    const append = () => {
        for (const row of rows.slice(offset, offset + 24)) body.append(render(row));
        offset += 24;
        if (offset < rows.length) {
            const more = u.button('显示更多' + noun + '（剩余 ' + (rows.length - offset) + ' 项）', () => {
                more.remove();
                append();
            });
            body.append(more);
        }
    };
    append();
}
const templateWarnings = {
    OTHER: '服务商还报告了当前插件无法识别的模板提醒',
    NO_GROUP_NODES: '策略组没有可用节点，服务商已将出口设为直连',
    UNSUPPORTED_SOURCE_RULES: '规则集中的部分规则无法用此模板表达，服务商已跳过',
    GLOBAL_TEST_URL: '模板使用统一的测速地址',
    UNSUPPORTED_RULE: '服务商已跳过此模板无法表达的规则',
    NODE_SUBSCRIPTION_REQUIRED: '此模板引用独立的节点订阅，请确认所引用的节点已导入',
    UNSUPPORTED_GROUP: '故障转移组已导出为手动选择组',
    REJECT_CANDIDATE: '模板无法让用户选择拦截出口，服务商已从可选成员中移除该项',
    STATIC_REJECT: '策略组已按默认设置固定为拦截',
    NODE_LIST_ONLY: '模板只下发节点，未附带服务商的分流规则',
    CUSTOM_TEMPLATE: '自定义模板未引用服务商生成的策略组和分流规则',
    NATIVE_LINK_UNAVAILABLE: '部分节点缺少生成分享链接所需的信息',
    UNSUPPORTED_NODE_OPTIONS: '部分节点的协议选项无法用此模板表达',
    NAIVE_CERTIFICATE_TRUST: 'Naive 节点需要路由器信任服务端证书',
};
const providerErrors = {
    provider_timeout: '请求超时', provider_dns_failed: '无法解析提供方域名',
    provider_tls_untrusted: 'HTTPS 证书校验失败', provider_connection_refused: '提供方拒绝连接',
    provider_unreachable: '无法连接提供方', private_provider_address: '提供方指向私有或本地地址，已阻止访问',
    provider_redirect_refused: '提供方重定向不符合下载策略', invalid_provider_url: '提供方下载地址无效',
    provider_limit: '引用的提供方数量超过上限', provider_size_limit: '提供方文件超过下载上限', provider_incomplete: '文件传输不完整',
    provider_kernel_unavailable: '下载此文件需要已选内核，请安装内核后刷新订阅',
    provider_detour_unavailable: '指定下载出口无法使用',
    provider_cancelled: '下载已取消', provider_download_failed: '引用文件下载失败',
    invalid_proxy_provider: '节点文件格式无效', invalid_rule_provider: '规则文件格式无效',
    duplicate_rule_provider: '规则集重复定义', node_limit: '节点数量超过上限', rule_limit: '规则数量超过上限',
};

function failureMessage(code, provider, tls) {
    const cert = tlsMessage(tls);
    if (!provider || provider.code !== code || !['node', 'rule'].includes(provider.kind)) return cert || notices[code] || providerErrors[code] || code;
    const http = /^provider_http_([1-5][0-9]{2})$/.exec(code);
    const label = provider.kind === 'rule' ? '规则提供方' : '节点提供方';
    const issue = [label, provider.file, http ? '返回 HTTP ' + http[1] : cert || providerErrors[code] || '引用文件读取失败'].filter(Boolean).join(' · ');
    const rows = provider.template_warnings ? noticeRows([{code:'platform_routing_warnings', at:provider.template_warnings}]) : [];
    return rows.length ? issue + '。模板提醒：' + rows.map(row => row.text).join('；') : issue;
}

function noticeRows(items = []) {
    return items.flatMap((n) => {
        if (n.code !== 'platform_routing_warnings') {
            const detail = missingRejectRule(n) ? '此拦截规则引用的规则集未载入' : notices[n.code] || n.code;
            return [{ count: 1, text: [n.at, n.resource, detail].filter(Boolean).join(' · ') }];
        }
        if (/^[0-9]+$/.test(n.at)) {
            return [{ count: Number(n.at), text: '服务商报告了 ' + n.at + ' 条模板提醒，仅提供了总数。' }];
        }
        return (n.at || '').split(',').map(item => {
            const [code, raw] = item.split('=');
            const count = Number(raw) || 1;
            return { count, text: (templateWarnings[code] || '服务商模板提醒') + (count > 1 ? '（' + count + ' 条）' : '') };
        });
    });
}
function missingRejectRule(n) {
    return n.code === 'rule_provider_reference_unavailable' && n.dangerous === true;
}
function noticeSummary(items) {
    const warnings = items || [];
    const rows = noticeRows(warnings);
    if (!rows.length) return '';
    const count = rows.reduce((n, row) => n + row.count, 0);
    return count + ' 条导入提醒' + (rows.length === 1 && !/^[0-9]+$/.test(warnings[0].at) ? ' · ' + rows[0].text : '');
}
function review(u, result) {
    const changes = result?.changes || {};
    const lines = [
        ['新增节点', changes.added?.map((x) => x.name)],
        ['移除节点', changes.removed?.map((x) => x.name)],
        ['受影响的策略组', changes.affected_groups?.map((id) => u.name(id) || id)],
        ['引用已失效', changes.missing_active_targets?.map((id) => u.name(id) || id)],
    ];
    const rows = noticeRows(result?.notices);
    const body = u.h(
        'div',
        { class: 'ow-stack' },
        ...lines
            .filter((x) => x[1]?.length)
            .map(([key, values]) =>
                u.h('details', {}, u.h('summary', {}, key + ' · ' + values.length), u.h('p', {}, values.join('、'))),
            ),
    );
    moreRows(u, body, rows, row => u.h('p', {}, row.text), '提醒');
    return body;
}
async function retryDownload(u, source, group, content, feedback, replacementURL, needsFile) {
    const select = choice(u, group.options.map(option => [option.id, option.name]), group.selected, '规则下载出口');
    const controls = [field(u, group.name || '规则下载出口', select), muted(u, '此选择仅用于本订阅的规则下载。')];
    if (group.total > group.options.length) controls.push(muted(u, '显示 ' + group.options.length + ' / ' + group.total + ' 个成员。'));
    const file = needsFile && !content ? fileControl(u) : null;
    if (file) controls.push(file.node);
    let retry = false;
    const dialog = u.dialog('选择规则下载出口', form(u, controls, '保存并重试', async () => {
        if (file) content = await file.text();
        await write(u, 'preferences', { source, preferences: { download_choice: { group: group.id, member: select.value } } });
        retry = true;
        dialog.close();
    }));
    await new Promise(resolve => dialog.addEventListener('close', resolve, { once: true }));
    return retry && !u.signal.aborted && importSource(u, source, content, feedback, undefined, replacementURL);
}
async function importSource(u, source, content, feedback, confirmation, replacementURL, present) {
    const previous = (u.sources || []).some((s) => s.source === source && s.ready);
    if (feedback) {
        feedback.hidden = false;
        feedback.textContent = content ? '正在导入…' : '正在更新…';
    }
    try {
        const r = await write(u, 'refresh', {
            source,
            ...(content ? { content } : {}),
            ...(confirmation ? { confirm: confirmation } : {}),
            ...(replacementURL ? { replacement_url: replacementURL } : {}),
        });
        if (u.signal.aborted) return false;
        if (r?.decision === 'confirmation_required') {
            if (feedback) feedback.textContent = '等待确认更改';
            const ask = () => confirm(
                u,
                '确认订阅变更',
                u.h('div', {},
                    u.h('p', {}, r.retains_routing ? '以下规则无法用于本次配置。确认后将跳过这些条目，保留其余分流规则和策略组。' : '部分配置无法按原样导入。应用前请核对以下变化。'),
                    r.notices?.some(missingRejectRule)
                        ? u.h('p', {class:'ow-warning'}, '此次变更会跳过拦截规则。原本由它拦截的流量会继续匹配其余规则和兜底出口。')
                        : null,
                    review(u, r),
                ),
                r.retains_routing ? '保留其余分流并应用' : '应用此版本',
                () => importSource(u, source, content, feedback, r.confirmation_id, replacementURL),
            );
            const ok = await (present ? present(ask) : ask());
            if (!ok && feedback) feedback.textContent = previous ? '已保留现有配置' : '已取消本次导入';
            return ok;
        }
        if (r?.decision !== 'ready') {
            const message = previous ? '已保留上次配置' : '此配置无法导入';
            if (feedback) feedback.textContent = message;
            const open = () => u.dialog(message, review(u, r));
            if (present) await present(() => new Promise(resolve => open().addEventListener('close', resolve, { once: true })));
            else open();
            return false;
        }
        if (feedback)
            feedback.replaceChildren(
                u.h('details', {}, u.h('summary', {}, ['更新完成', r.node_count + ' 个节点', noticeSummary(r.notices)].filter(Boolean).join(' · ')), review(u, r)),
            );
        return true;
    } catch (err) {
        const description = failureMessage(err.message, err.provider, err.tls);
        if (feedback) {
            feedback.textContent = '更新失败 · ' + description + (previous ? ' · 已保留上次配置' : '');
        }
        const group = err.provider?.download_group;
        if (group?.options?.length && !u.signal.aborted) {
            const retry = () => retryDownload(u, source, group, content, feedback, replacementURL, false);
            if (!feedback) return present ? present(retry) : retry();
            feedback.append(' ', u.button('选择规则下载出口', async () => { if (await retry()) await u.refresh(); }));
            return false;
        }
        if (description !== err.message) throw new Error(description);
        throw err;
    }
}
async function chooseSource(u, s) {
    if (!s.ready && !(await importSource(u, s.source))) return;
    await u.run('source', { source: s.source });
    await u.refresh();
}
function agentField(u, agents, existing) {
    const choices = [...agents.map((x) => [x, x]), ['custom', '自定义 UA']];
    const selected = existing?.custom_agent ? 'custom' : existing?.agent || agents[0];
    const sel = choice(u, choices, selected, '订阅请求 UA');
    const custom = input(u, {
        type: 'text',
        maxlength: 256,
        placeholder: existing?.custom_agent ? '留空保留当前自定义 UA' : 'User-Agent',
        autocomplete: 'off',
        'aria-label': '自定义 UA',
    });
    const update = () => {
        custom.hidden = sel.value !== 'custom';
        custom.disabled = custom.hidden;
        custom.required = !custom.hidden && !existing?.custom_agent;
    };
    sel.addEventListener('change', update);
    update();
    return {
        node: u.h('div', { class: 'ow-stack' }, field(u, '订阅请求 UA', sel), custom),
        values: () => ({
            user_agent: sel.value === 'custom' ? custom.value.trim() : sel.value,
            keep_user_agent: !!existing?.custom_agent && sel.value === 'custom' && !custom.value.trim(),
        }),
    };
}
function fileControl(u) {
    const f = input(u, {
        type: 'file',
        required: true,
        accept: '.json,.yml,.yaml,.txt,.conf,.ini,.list,.sub,text/plain',
        'aria-label': '选择配置文件',
    });
    return {
        input: f,
        node: field(u, '配置文件', f),
        text: async () => {
            const item = f.files[0];
            // rpcd/ubus can have a smaller transport limit than the importer.
            if (!item || item.size > 8 * 1024 * 1024) throw Error('请选择 8 MiB 以内的配置文件');
            return item.text();
        },
    };
}
function reimport(u, source, feedback) {
    const f = fileControl(u);
    const dialog = u.dialog(
        '导入新文件',
        form(u, [f.node], '导入', async () => {
            const ok = await importSource(u, source, await f.text(), feedback);
            dialog.close();
            if (ok) await u.refresh();
        }),
    );
}
function login(u, mount, close) {
    const origin = input(u, { type: 'url', required: true, placeholder: 'https://', autocomplete: 'url' });
    mount.replaceChildren(
        form(u, [field(u, '服务商地址', origin)], '验证服务商', async () => {
            const url = new URL(origin.value.trim());
            if (
                url.protocol !== 'https:' ||
                url.pathname !== '/' ||
                url.search ||
                url.hash ||
                url.username ||
                url.password
            )
                throw Error('请填写服务商 HTTPS 站点地址');
            const site = await write(u, 'site', { origin: url.origin });
            const email = input(u, { type: 'email', required: true, autocomplete: 'username' });
            const password = input(u, { type: 'password', required: true, autocomplete: 'current-password' });
            mount.replaceChildren(
                form(
                    u,
                    [
                        u.h('strong', {}, site.name),
                        muted(u, url.host),
                        field(u, '邮箱', email),
                        field(u, '密码', password),
                    ],
                    '登录',
                    async () => {
                        const data = await write(u, 'login', {
                            origin: url.origin,
                            email: email.value.trim(),
                            password: password.value,
                        });
                        password.value = '';
                        const plans = data.plans || [];
                        const usable = plans.filter(p => p.usable);
                        const automatic = !u.status.saved?.source && usable.length === 1 ? usable[0] : null;
                        const feedback = u.h('div', { role: 'status', class: 'ow-muted', hidden: true });
                        const finish = async () => { close(); await u.refresh(); };
                        async function load(i, choose) {
                            if (await importSource(u, data.sources[i], '', feedback)) {
                                if (choose) await u.run('source', {source: data.sources[i]});
                                await finish();
                            }
                        }
                        let retry;
                        const rows = plans.map((p, i) => {
                            const auto = p === automatic;
                            const label = !p.usable ? '暂不可用' : auto ? '重新下载' : '使用';
                            const button = u.button(label, () => load(i, !auto));
                            button.disabled = !p.usable;
                            if (auto) {
                                retry = button;
                                retry.disabled = true;
                            }
                            return u.h(
                                'div',
                                { class: 'ow-row' },
                                u.h(
                                    'div',
                                    {},
                                    u.h('strong', {}, p.planName || '套餐'),
                                    u.h('div', { class: 'ow-muted' }, p.expireAt ? '到期 ' + date(p.expireAt) : '长期有效'),
                                ),
                                button,
                            );
                        });
                        mount.replaceChildren(
                            u.h('h3', {}, automatic ? '导入套餐' : '选择套餐'),
                            ...rows, feedback,
                            ...(rows.length ? [] : [muted(u, '账户暂无套餐')]),
                            u.button('完成', finish),
                        );
                        if (automatic) {
                            try { await load(plans.indexOf(automatic), false); }
                            finally { retry.disabled = false; }
                        }
                    },
                ),
            );
        }),
    );
}
async function saveNewSource(u, config, content, close) {
    await write(u, 'configure', { config });
    if (!(await importSource(u, config.id, content))) return false;
    if (close) close();
    await u.refresh();
    return true;
}
export function onboarding(u, environment, trigger) {
    const body = u.h('div', { class: 'ow-onboarding' });
    const dialog = u.dialog('启用全屋代理', body);
    const close = () => dialog.close();
    dialog.addEventListener('close', () => {
        if (trigger.isConnected && !document.querySelector('dialog[open]')) trigger.focus({ preventScroll: true });
    }, { once: true });
    const loginPane = u.h('div', { class: 'ow-stack' });
    login(u, loginPane, close);
    const link = input(u, { type: 'url', required: true, placeholder: 'https://…', autocomplete: 'off' });
    const f = fileControl(u);
    const linkID = 'src-' + ids(),
        fileID = 'src-' + ids();
    const picker = u.button('或导入配置文件', () => f.input.click(), 'ow-link');
    f.input.hidden = true;
    const progress = u.h('span', { role: 'status', class: 'ow-muted' });
    f.input.addEventListener('change', async () => {
        if (!f.input.files?.[0]) return;
        const name = f.input.files[0].name || '本地配置';
        picker.disabled = true;
        progress.textContent = '正在导入…';
        try {
            await saveNewSource(u, { id: fileID, kind: 'file', name: name.slice(0, 128) }, await f.text(), close);
        } catch (e) {
            u.notify(e.message);
        } finally {
            picker.disabled = false;
            progress.textContent = '';
            f.input.value = '';
        }
    });
    const linkForm = form(u, [field(u, '粘贴订阅链接', link)], '添加订阅', async () => {
        const address = new URL(link.value.trim());
        await saveNewSource(u, { id: linkID, kind: 'external', name: address.hostname, url: address.href }, '', close);
    });
    linkForm.querySelector('button[type=submit]').className = 'ow-secondary-submit';
    body.append(
        muted(u, '登录 OpenWeir 服务商，或直接添加订阅链接、导入配置文件。'),
        u.h('section', { class: 'ow-setup-section' }, u.h('h3', {}, '登录 OpenWeir 服务商'), loginPane),
        u.h('section', { class: 'ow-setup-section' }, linkForm, actions(u, picker, f.input, progress)),
        u.h('h3', {}, '运行环境检查'),
        environment,
    );
}
async function addSource(u, agents) {
    const host = u.h('div', { class: 'ow-stack' }),
        pane = u.h('div', { class: 'ow-stack' });
    const dialog = u.dialog('添加订阅', host);
    const tabs = u.h('div', { class: 'ow-segment', role: 'group', 'aria-label': '订阅类型' });
    host.append(tabs, pane);
    function select(kind) {
        [...tabs.children].forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.kind === kind)));
        if (kind === 'platform') {
            login(u, pane, () => dialog.close());
            return;
        }
        const filename = input(u, { type: 'text', maxlength: 128, required: true, placeholder: '订阅名称' });
        const link = input(u, { type: 'url', required: true, placeholder: 'https://', autocomplete: 'off' });
        const f = fileControl(u),
            a = agentField(u, agents);
        const configured = { id: '' };
        pane.replaceChildren(
            form(
                u,
                [field(u, '名称', filename), ...(kind === 'file' ? [f.node] : [field(u, '订阅链接', link), a.node])],
                '添加并导入',
                async () => {
                    const content = kind === 'file' ? await f.text() : '';
                    if (!configured.id) configured.id = 'src-' + ids();
                    const config = { id: configured.id, name: filename.value.trim(), kind };
                    if (kind === 'external') {
                        config.url = link.value.trim();
                        config.user_agent = a.values().user_agent;
                    }
                    await saveNewSource(u, config, content, () => dialog.close());
                },
            ),
        );
    }
    for (const [key, title] of [
        ['external', '订阅链接'],
        ['platform', '服务商登录'],
        ['file', '本地文件'],
    ]) {
        const b = u.button(title, () => select(key));
        b.dataset.kind = key;
        tabs.append(b);
    }
    select('external');
}
function editSource(u, s, agents) {
    const a = s.kind === 'external' ? agentField(u, agents, s) : null;
    const name = input(u, { type: 'text', value: s.name || '', required: true, maxlength: 128 });
    const fallback = input(u, { type: 'checkbox' });
    fallback.checked = !!s.local_fallback;
    const controls = [];
    if (s.kind !== 'platform') controls.push(field(u, '名称', name));
    if (a) controls.push(a.node);
    controls.push(field(u, '可转换时允许使用本地分流', fallback));
    const body = u.h('div', { class: 'ow-stack' });
    const dialog = u.dialog('编辑订阅', body);
    body.append(
        form(u, controls, '保存', async () => {
            const preferences = {
                ...(a ? a.values() : {}),
                ...(s.kind === 'platform' ? {} : { name: name.value.trim() }),
                allow_local_fallback: fallback.checked,
            };
            await write(u, 'preferences', { source: s.source, preferences });
            dialog.close();
            await u.refresh();
        }),
    );
    const other = [];
    if (s.download_override) other.push(u.button('恢复订阅指定的下载出口', async () => {
        await write(u, 'preferences', { source: s.source, preferences: { download_choice: { group: '', member: '' } } });
        dialog.close();
        await u.refresh();
    }));
    if (s.kind === 'external')
        other.push(
            u.button('更换订阅链接', () => {
                const url = input(u, { type: 'url', required: true, placeholder: 'https://', autocomplete: 'off' });
                const child = u.dialog(
                    '更换订阅链接',
                    form(u, [field(u, '新订阅链接', url)], '验证并更换', async () => {
                        const ok = await importSource(u, s.source, undefined, undefined, undefined, url.value.trim());
                        if (!ok) return;
                        child.close();
                        dialog.close();
                        await u.refresh();
                    }),
                );
            }),
        );
    if (s.has_history)
        other.push(
            u.button('恢复上一份快照', () =>
                confirm(u, '恢复上一份快照', muted(u, s.name), '恢复', async () => {
                    await write(u, 'rollback', { source: s.source });
                    dialog.close();
                    await u.refresh();
                }),
            ),
        );
    const title = s.kind === 'platform' ? '退出服务商账户' : '移除订阅';
    other.push(
        u.button(
            title,
            () =>
                confirm(
                    u,
                    title,
                    u.h(
                        'p',
                        {},
                        s.kind === 'platform'
                            ? '此账户下所有套餐的凭据和快照都将移除。'
                            : '此订阅的节点、规则和历史快照都将移除。',
                    ),
                    title,
                    async () => {
                        await write(u, s.kind === 'platform' ? 'logout' : 'revoke', { source: s.source });
                        dialog.close();
                        await u.refresh();
                    },
                ),
            'ow-danger',
        ),
    );
    body.append(actions(u, ...other));
}
export async function subscriptions(u) {
    const [agents, prefs] = await Promise.all([read(u, 'agents'), u.rpc('network_preferences').catch(() => ({}))]),
        sources = (u.sources || []).filter((s) => !s.revoked);
    const current = u.status.intent?.source;
    const feedback = new Map(),
        grid = u.h('div', { class: 'ow-source-grid ow-grid' });
    const canRefresh = (s) => s.kind !== 'file' && !s.login_required;
    const updateAll = u.button('全部更新', async () => {
        const errors = [];
        const queue = sources.filter(canRefresh)[Symbol.iterator]();
        // At most two transfers at once on the router. Review one plan at a time.
        let reviewDone = Promise.resolve();
        const present = show => {
            const next = reviewDone.then(() => !u.signal.aborted && show());
            reviewDone = next.catch(() => {});
            return next;
        };
        const worker = async () => {
            for (const s of queue) {
                if (u.signal.aborted) return;
                try {
                    await importSource(u, s.source, '', feedback.get(s.source), undefined, undefined, present);
                } catch {
                    errors.push(s.name);
                }
            }
        };
        await Promise.all([worker(), worker()]);
        if (!u.signal.aborted) {
            await u.refresh();
            if (errors.length) u.notify('更新失败 · ' + errors.join('、'));
        }
    });
    updateAll.disabled = !sources.some(canRefresh);
    function sourceCard(s) {
        const warning = noticeSummary(s.notices);
        const message = u.h(
            'div',
            { class: 'ow-muted', role: 'status', hidden: !s.last_failure && !s.last_change && !s.needs_refresh },
            s.last_failure
                ? '上次更新失败 · ' + failureMessage(s.last_failure, s.last_provider, s.last_tls) + (s.ready ? ' · 已保留上次配置' : '')
                : s.needs_refresh ? (s.kind === 'file' ? '内核已切换，请重新导入原文件以生成配置' : '内核已切换，等待重新获取订阅')
                : s.last_change
                  ? '上次更新 · 新增 ' + s.last_change.added + ' · 移除 ' + s.last_change.removed
                  : '',
        );
        if (s.last_provider?.download_group?.options?.length && !s.suspended && !s.login_required) {
            message.append(' ', u.button('选择规则下载出口', async () => {
                if (await retryDownload(u, s.source, s.last_provider.download_group, undefined, message, undefined, s.kind === 'file')) await u.refresh();
            }));
        }
        feedback.set(s.source, message);
        const isCurrent = current === s.source;
        const use = isCurrent ? badge(u, '正在使用') : u.button('设为当前', () => chooseSource(u, s));
        if (!isCurrent) use.disabled = !!s.suspended || !!s.login_required || (!s.ready && s.kind === 'file');
        const avatar = u.h('span', { class: 'ow-avatar', 'aria-hidden': 'true' }, Array.from(s.name || '订阅')[0]);
        const agentLabel = s.kind === 'external' && (s.custom_agent ? '自定义 UA' : s.agent);
        const interval = s.kind !== 'file' && Number.isInteger(prefs.update_hours)
            ? (prefs.update_hours > 0 ? '每 ' + prefs.update_hours + ' 小时自动更新' : '手动更新')
            : '';
        const meta = [kinds[s.kind], formats[s.format] || s.format, agentLabel, interval]
            .filter(Boolean)
            .join(' · ');
        const plan = s.usage || s.plan,
            used = plan ? (Number(plan.upload) || 0) + (Number(plan.download) || 0) : 0;
        const planInfo = plan
            ? u.h(
                  'div',
                  { class: 'ow-stack' },
                  ...(plan.total > 0
                      ? [
                            u.h('progress', {
                                value: Math.min(used, plan.total),
                                max: plan.total,
                                'aria-label': '已用套餐流量',
                            }),
                        ]
                      : []),
                  u.h(
                      'div',
                      { class: 'ow-row' },
                      muted(u, bytes(used) + (plan.total != null ? ' / ' + bytes(plan.total) : '')),
                      muted(
                          u,
                          plan.expireAt
                              ? '到期 ' + new Date(plan.expireAt).toLocaleDateString()
                              : !s.usage || s.usage.no_expiry
                                ? '长期有效'
                                : '',
                      ),
                  ),
              )
            : null;
        const metadata = u.h(
            'div',
            { class: 'ow-row' },
            u.h('span', {}, u.h('strong', { class: 'ow-mono' }, String(s.node_count || 0)), ' 个节点'),
            muted(u, s.updated_at ? '上次更新 ' + date(s.updated_at) : '尚未更新'),
        );
        const update = u.button(s.kind === 'file' ? '导入新文件' : s.login_required ? '重新登录' : '更新', () => {
            if (s.kind === 'file') return reimport(u, s.source, message);
            if (s.login_required) {
                const pane = u.h('div', {}),
                    d = u.dialog('登录服务商', pane);
                return login(u, pane, () => d.close());
            }
            return importSource(u, s.source, '', message).then(async ok => {
                if (!ok || u.signal.aborted) return;
                const updated = await read(u, 'status', {source: s.source});
                if (u.signal.aborted) return;
                if (updated.revoked || !updated.source) return u.refresh();
                const index = sources.indexOf(s);
                if (index < 0) return;
                sources[index] = updated;
                const original = u.sources.indexOf(s);
                if (original >= 0) u.sources[original] = updated;
                const replacement = sourceCard(updated);
                card.replaceWith(replacement);
                updateAll.disabled = !sources.some(canRefresh);
            });
        });
        const card = u.h(
            'section',
            { class: 'ow-card ow-source-card' },
            u.h(
                'div',
                { class: 'ow-source-title' },
                avatar,
                u.h(
                    'div',
                    { class: 'ow-source-info' },
                    u.h('strong', {}, s.name || '订阅'),
                    u.h('div', { class: 'ow-muted' }, meta),
                ),
                use,
            ),
            metadata,
            ...(planInfo ? [planInfo] : []),
            ...(s.suspended ? [badge(u, '套餐暂不可用')] : []),
            ...(warning ? [u.h('details', {}, u.h('summary', {}, warning), review(u, s))] : []),
            message,
            actions(
                u,
                update,
                u.button('编辑', () => editSource(u, s, agents)),
            ),
        );
        return card;
    }
    grid.append(...sources.map(sourceCard));
    const add = u.button('＋ 添加订阅', () => addSource(u, agents), 'ow-primary');
    const body = u.h(
        'div',
        { class: 'ow-stack' },
        u.h('div', { class: 'ow-row ow-toolbar' }, u.h('h2', {}, '订阅'), actions(u, updateAll, add)),
        sources.length
            ? grid
            : u.h(
                  'div',
                  { class: 'ow-card ow-empty' },
                  u.h('h3', {}, '尚未添加订阅'),
                  muted(u, '登录服务商、粘贴订阅链接或从文件导入节点。'),
              ),
    );
    if (u.detail === 'add') u.afterRender = () => {
        history.replaceState(history.state, '', '#subscriptions');
        addSource(u, agents);
    };
    return body;
}

const matchType = {
    domain: 'DOMAIN',
    domain_suffix: 'DOMAIN-SUFFIX',
    domain_keyword: 'DOMAIN-KEYWORD',
    ip_cidr: 'IP-CIDR',
    source_ip_cidr: 'SRC-IP',
    source_mac_address: 'SRC-MAC',
    network: 'NETWORK',
    port: 'PORT',
    port_range: 'PORT-RANGE',
    protocol: 'PROTOCOL',
    ip_version: 'IP-VERSION',
    ip_is_private: 'PRIVATE',
    rule_set: 'RULE-SET',
};
const editorTypes = [
    ['domain', '域名'],
    ['domain_suffix', '域名后缀'],
    ['domain_keyword', '域名关键词'],
    ['ip_cidr', '目标 IP 网段'],
    ['source_ip_cidr', '来源 IP 网段'],
    ['network', 'TCP / UDP'],
    ['port', '目标端口'],
    ['port_range', '端口范围'],
    ['protocol', '流量协议'],
    ['ip_version', 'IP 版本'],
];
const routeName = (u, target) =>
    ({ '@direct': '直连', '@reject': '拦截', '@global': '全局', '@default': '默认代理' })[target] || u.name(target);
function describeRule(match) {
    return Object.entries(match || {}).map(([k, v]) => ({
        type: matchType[k] || k,
        value:
            k === 'ip_is_private'
                ? '私有地址'
                : (Array.isArray(v) ? v : [v])
                      .map((value) => (typeof value === 'object' ? JSON.stringify(value) : String(value)))
                      .join('、'),
    }));
}
function targetLink(u, id) {
    if (!id || id === '@direct' || id === '@reject') return badge(u, routeName(u, id));
    return u.button(routeName(u, id) + ' ›', () => u.go('proxy', id));
}
async function allGroups(u, source) {
    const groups = [];
    for (let offset = 0; ; offset += 256) {
        if (u.signal?.aborted) throw new DOMException('页面已切换', 'AbortError');
        const page = await read(u, 'groups', { source, limit: 256, offset });
        groups.push(...page.items);
        if (groups.length >= page.total || page.items.length < 256) return groups;
    }
}
function matchValue(key, typed) {
    const values = typed
        .split(/[,，\n]/)
        .map((v) => v.trim())
        .filter(Boolean);
    if (!values.length) throw Error('请输入匹配内容');
    if (key === 'port' || key === 'ip_version') {
        const nums = values.map((v) => (/^\d+$/.test(v) ? Number(v) : NaN));
        if (nums.some((n) => !Number.isInteger(n) || (key === 'port' ? n < 1 || n > 65535 : n !== 4 && n !== 6)))
            throw Error('无效的端口或 IP 版本');
        if (key === 'ip_version') {
            if (nums.length !== 1) throw Error('请选择一个 IP 版本');
            return nums[0];
        }
        return nums;
    }
    if (key === 'network' && values.some((v) => !['tcp', 'udp'].includes(v.toLowerCase())))
        throw Error('网络类型必须为 tcp 或 udp');
    return key === 'network' ? values.map((v) => v.toLowerCase()) : values;
}
async function editRule(u, custom, index, source, isLocal) {
    const old = custom[index],
        key = Object.keys(old?.match || { domain_suffix: '' })[0];
    const complex = old && (Object.keys(old.match).length !== 1 || !editorTypes.some(([k]) => k === key));
    const kind = choice(u, editorTypes, key, '匹配类型');
    const val = input(u, {
        required: true,
        placeholder: 'example.com',
        value: old ? [old.match[key]].flat().join(', ') : '',
    });
    const targets = [
        ['@direct', '直连'],
        ['@reject', '拦截'],
    ];
    if (isLocal) targets.push(['@default', '默认代理']);
    if (source && u.sources?.some((s) => s.source === source && s.ready))
        for (const g of u.ruleGroups || (await allGroups(u, source))) targets.push([g.id, g.name]);
    for (const g of u.status.intent?.policy?.groups || []) targets.push([g.id, g.name]);
    if (old && !targets.some(([id]) => id === old.target))
        targets.push([old.target, '不可用 · ' + routeName(u, old.target)]);
    const target = choice(u, targets, old?.target || '@direct', '去向');
    const note = input(u, { value: old?.note || '', maxlength: 256 }),
        enabled = input(u, { type: 'checkbox' });
    enabled.checked = old?.enabled !== false;
    const raw = u.h('textarea', { rows: 5, required: true, spellcheck: false, 'aria-label': '匹配条件 JSON' });
    if (complex) raw.value = JSON.stringify(old.match, null, 2);
    const controls = complex
        ? [field(u, '匹配条件 JSON', raw)]
        : [field(u, '类型', kind), field(u, '匹配内容（多个值以逗号分隔）', val)];
    const save = async (list) => {
        await u.run('save_rules', { args: list, revision: u.status.intent.revision });
        await u.refresh();
    };
    const body = u.h('div', { class: 'ow-stack' }),
        dialog = u.dialog(old ? '编辑规则' : '添加自定义规则', body);
    body.append(
        form(
            u,
            [...controls, field(u, '去向', target), field(u, '说明', note), field(u, '启用规则', enabled)],
            '保存',
            async () => {
                let match;
                if (complex) {
                    try {
                        match = JSON.parse(raw.value);
                    } catch {
                        throw Error('匹配条件必须是有效的 JSON 对象');
                    }
                    if (
                        !match ||
                        Array.isArray(match) ||
                        typeof match !== 'object' ||
                        !Object.keys(match).length ||
                        Object.keys(match).some((k) => !editorTypes.some(([key]) => key === k))
                    )
                        throw Error('存在不支持的匹配条件');
                } else {
                    match = { [kind.value]: matchValue(kind.value, val.value) };
                }
                const rule = {
                    ...old,
                    id: old?.id || 'rule-' + ids(),
                    match,
                    target: target.value,
                    note: note.value.trim(),
                    enabled: enabled.checked,
                };
                const next = custom.slice();
                if (old) next[index] = rule;
                else next.push(rule);
                await save(next);
                dialog.close();
            },
        ),
    );
    if (old)
        body.append(
            u.button(
                '删除规则',
                () =>
                    confirm(
                        u,
                        '删除规则',
                        muted(
                            u,
                            describeRule(old.match)
                                .map((x) => x.value)
                                .join(' · '),
                        ),
                        '删除',
                        async () => {
                            await save(custom.filter((_, i) => i !== index));
                            dialog.close();
                        },
                    ),
                'ow-danger',
            ),
        );
}
const limitRules = 50;
export async function rules(u) {
    const source = u.status.intent?.source,
        primary = (u.sources || []).find((s) => s.source === source),
        ready = primary?.ready;
    const tab = ['custom', 'sets'].includes(u.detail) ? u.detail : 'effective';
    const menu = u.h('div', { class: 'ow-segment', role: 'group', 'aria-label': '规则页面' });
    for (const [id, title] of [
        ['effective', '生效规则'],
        ['custom', '自定义规则'],
        ['sets', '规则集'],
    ]) {
        const b = u.button(title, () => u.go('rules', id === 'effective' ? '' : id));
        b.setAttribute('aria-pressed', String(id === tab));
        menu.append(b);
    }
    const [customResponse, groups] = await Promise.all([u.rpc('custom_rules'), ready ? allGroups(u, source) : []]);
    const name = u.name,
        labels = new Map([...groups, ...(u.status.intent?.policy?.groups || [])].map((g) => [g.id, g.name]));
    u = { ...u, ruleGroups: groups, name: (id) => labels.get(id) || name(id) };
    const custom = customResponse.items || [];
    const emptyPage = { items: [], positions: [], sets: {}, binary: {}, total: 0, local: false };
    const initial = ready ? await read(u, 'rules', { source, limit: limitRules }) : emptyPage;
    const mode = u.status.intent?.mode,
        content = u.h('div', { class: 'ow-stack' }),
        body = u.h('div', { class: 'ow-stack' }, menu, content);
    const move = async (from, to) => {
        if (from === to || to < 0 || to >= custom.length) return;
        const list = custom.slice();
        list.splice(to, 0, list.splice(from, 1)[0]);
        await u.run('save_rules', { args: list, revision: u.status.intent.revision });
        await u.refresh();
    };
    if (tab === 'custom') {
        const rows = u.h('div', { class: 'ow-rule-list' });
        let dragging = -1;
        for (const [i, r] of custom.entries()) {
            const up = u.button('↑', () => move(i, i - 1)),
                down = u.button('↓', () => move(i, i + 1));
            up.setAttribute('aria-label', '上移第 ' + (i + 1) + ' 条规则');
            down.setAttribute('aria-label', '下移第 ' + (i + 1) + ' 条规则');
            up.disabled = i === 0;
            down.disabled = i === custom.length - 1;
            const detail = describeRule(r.match);
            const row = u.h(
                'div',
                { class: 'ow-rule-row', draggable: 'true' },
                u.h('span', { class: 'ow-mono' }, String(i + 1)),
                u.h(
                    'div',
                    {},
                    u.h('strong', {}, detail.map((x) => x.value).join(' · ')),
                    u.h('div', { class: 'ow-muted' }, detail.map((x) => x.type).join(' + ')),
                ),
                targetLink(u, r.target),
                u.h('div', { class: 'ow-muted' }, r.note || '', r.enabled === false ? badge(u, '已停用') : null),
                actions(
                    u,
                    up,
                    down,
                    u.button('编辑', () => editRule(u, custom, i, source, initial.local)),
                ),
            );
            row.addEventListener('dragstart', (e) => {
                dragging = i;
                e.dataTransfer.effectAllowed = 'move';
                e.dataTransfer.setData('text/plain', String(i));
            });
            row.addEventListener('dragend', () => {
                dragging = -1;
            });
            row.addEventListener('dragover', (e) => {
                if (dragging >= 0) e.preventDefault();
            });
            row.addEventListener('drop', async (e) => {
                e.preventDefault();
                const old = dragging;
                dragging = -1;
                if (old >= 0)
                    try {
                        await move(old, i);
                    } catch (err) {
                        u.notify(err.message);
                    }
            });
            rows.append(row);
        }
        content.append(
            u.h(
                'section',
                { class: 'ow-card' },
                u.h(
                    'div',
                    { class: 'ow-row ow-toolbar' },
                    u.h('h2', {}, '自定义规则'),
                    u.button('＋ 添加规则', () => editRule(u, custom, -1, source, initial.local), 'ow-primary'),
                ),
                custom.length ? rows : u.h('p', { class: 'ow-empty' }, '暂无自定义规则'),
            ),
        );
        return body;
    }
    const names = Object.keys(initial.sets || {});
    if (initial.local) names.push(...['geosite-cn', 'geoip-cn'].filter((s) => !names.includes(s)));
    if (tab === 'sets') {
        const area = u.h('div', { class: 'ow-rule-list' }),
            feedback = u.h('div', { class: 'ow-muted', role: 'status', hidden: true });
        const btn = u.button('更新订阅规则集', () =>
            primary?.kind === 'file' ? reimport(u, source, feedback) : importSource(u, source, '', feedback),
        );
        btn.disabled = !ready || initial.local || !names.length;
        for (const name of names) {
            const builtIn = !!initial.local,
                binary = !!initial.binary?.[name],
                count = initial.sets[name];
            area.append(
                u.h(
                    'div',
                    { class: 'ow-rule-row' },
                    u.h('strong', {}, name),
                    muted(u, builtIn ? '内置' : '订阅'),
                    muted(
                        u,
                        builtIn
                            ? '随插件更新'
                            : binary
                              ? (initial.entries?.[name] ?? '—') + ' 条 · 二进制'
                              : count + ' 条规则',
                    ),
                    muted(u, !builtIn && primary?.updated_at ? date(primary.updated_at) : ''),
                    u.button('查看规则', () => u.go('rules', 'set:' + name)),
                ),
            );
        }
        content.append(
            u.h(
                'section',
                { class: 'ow-card' },
                u.h('div', { class: 'ow-row ow-toolbar' }, u.h('h2', {}, '规则集'), btn),
                feedback,
                names.length ? area : u.h('p', { class: 'ow-empty' }, '当前来源没有规则集'),
            ),
        );
        return body;
    }
    const initialFilter = u.detail?.startsWith('set:') ? u.detail.slice(4) : '';
    const filter = choice(
        u,
        [['', '全部规则集'], ...names.map((s) => [s, s])],
        names.includes(initialFilter) ? initialFilter : '',
        '按规则集筛选',
    );
    const list = u.h('div', { class: 'ow-rule-list' }),
        pager = u.h('div', { class: 'ow-actions' }),
        summary = u.h('p', { class: 'ow-muted', role: 'status' });
    const card = u.h(
        'section',
        { class: 'ow-card' },
        u.h('div', { class: 'ow-row ow-toolbar' }, u.h('h2', {}, '规则'), filter),
        summary,
        list,
        pager,
    );
    content.append(card);
    const prepend = [];
    function effective(number, r, action) {
        const detail = describeRule(r.match);
        return u.h(
            'div',
            { class: 'ow-rule-row ow-effective-rule' },
            u.h('span', { class: 'ow-rule-number ow-mono' }, String(number)),
            u.h('span', { class: 'ow-rule-type ow-muted' }, detail.map(x => x.type).join(' + ')),
            u.h('strong', { class: 'ow-rule-match' }, detail.map(x => x.value).join(' · ')),
            targetLink(u, r.target),
            action || null,
        );
    }
    if (ready && mode !== 'direct') {
        prepend.push({ match: { ip_is_private: true }, target: '@direct' });
        for (const d of u.status.intent?.policy?.devices || [])
            if (d.target !== '@proxy' && (mode === 'smart' || d.target === '@direct'))
                prepend.push({
                    match: {
                        [/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(d.address) ? 'source_mac_address' : 'source_ip_cidr']:
                            d.address,
                    },
                    target: d.target,
                });
        if (mode === 'smart' && u.status.intent?.policy?.default_direct) {
            const explicit = (u.status.intent.policy.devices || [])
                .filter((d) => d.target === '@proxy')
                .map((d) => d.address);
            prepend.push({
                match: { LAN: explicit.length ? '默认设备（除 ' + explicit.join('、') + '）' : '默认设备' },
                target: '@direct',
            });
        }
        if (mode === 'smart')
            for (const [i, r] of custom.entries()) if (r.enabled !== false) prepend.push({ ...r, edit: i });
    }
    let seq = 0;
    async function renderPage(offset) {
        const token = ++seq,
            tag = filter.value;
        const data =
            mode === 'smart' && ready && !initial.local
                ? !offset && !tag
                    ? initial
                    : await read(u, 'rules', { source, offset, limit: limitRules, rule_set: tag })
                : emptyPage;
        if (token !== seq || u.signal?.aborted) return;
        list.replaceChildren();
        pager.replaceChildren();
        if (!ready) {
            summary.textContent = '选择可用订阅后显示匹配顺序。';
            return;
        }
        summary.textContent = mode === 'direct' ? '直连模式' : mode === 'global' ? '全局模式' : '智能分流 · 按匹配顺序';
        if (!tag && !offset)
            prepend.forEach((r, i) =>
                list.append(
                    effective(
                        i + 1,
                        r,
                        r.edit !== undefined
                            ? u.button('编辑', () => editRule(u, custom, r.edit, source, initial.local))
                            : null,
                    ),
                ),
            );
        data.items.forEach((r, i) =>
            list.append(effective(prepend.length + (data.positions?.[i] || offset + i + 1), r)),
        );
        if (initial.local && mode === 'smart' && (!tag || names.includes(tag)))
            list.append(
                effective(prepend.length + 1, {
                    match: { rule_set: tag || ['geosite-cn', 'geoip-cn'] },
                    target: '@direct',
                }),
            );
        if (offset + limitRules >= data.total && !tag) {
            const target =
                mode === 'direct'
                    ? '@direct'
                    : mode === 'global'
                      ? '@global'
                      : initial.local
                        ? '@default'
                        : initial.final || groups[0]?.id;
            if (target)
                list.append(
                    effective(prepend.length + (initial.local && mode === 'smart' ? 1 : data.total) + 1, {
                        match: { MATCH: '其余流量' },
                        target,
                    }),
                );
        }
        if (!list.children.length) list.append(u.h('p', { class: 'ow-empty' }, '当前模式下没有命中此筛选的规则'));
        if (data.total > limitRules) {
            const prev = u.button('上一页', () => renderPage(offset - limitRules)),
                next = u.button('下一页', () => renderPage(offset + limitRules));
            prev.disabled = !offset;
            next.disabled = offset + limitRules >= data.total;
            pager.append(
                prev,
                muted(u, Math.floor(offset / limitRules + 1) + ' / ' + Math.ceil(data.total / limitRules)),
                next,
            );
        }
    }
    filter.addEventListener('change', () => renderPage(0).catch((e) => u.notify(e.message)));
    await renderPage(0);
    return body;
}
