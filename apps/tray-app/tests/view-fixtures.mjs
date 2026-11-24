// 设置窗/弹层显示语义夹具测试（M-SET-UX-03「怎么验证」：Hub-only / P2P /
// 无 RTT / 未握手 / 旧快照 / 读取失败六种夹具 + zone 契约）。
// 跑法：node tests/view-fixtures.mjs（纯逻辑，无 Tauri/Windows 依赖）。
// 语义基准 = 旧入口（popup.html 既有显示）+ state.rs state_tier 口径。
import assert from 'node:assert/strict';
import {
  tierOf, fmtBytes, fmtEpoch, clockOf, fmtUpdatedAt,
  pickWgInterface, isTunnelUp, summarizePeers, newestHandshakeAt,
  directPeerRows, wgPeerRows, ZONE_MAP,
} from '../view-logic.js';

// 语言包最小桩（与 index.html / popup.html 实际键值一致）。
const T = {
  zh: { never: '从未', noSample: '无样本', unitMs: 'ms', lastUpdate: '最后更新' },
  en: { never: 'never', noSample: 'no sample', unitMs: 'ms', lastUpdate: 'Updated' },
};

// 固定「现在」= 2027-01-15T08:00:00Z（epoch 1_800_000_000），时间断言确定性。
const NOW = 1_800_000_000;
const NOW_MS = NOW * 1000;

let passed = 0;
const failures = [];

/** 夹具跑器：逐条登记 PASS/FAIL，收尾打印数字并按失败退出非零。 */
function fixture(name, fn) {
  try {
    fn();
    passed += 1;
    console.log(`ok  ${name}`);
  } catch (error) {
    failures.push(name);
    console.error(`FAIL ${name}\n    ${error.message}`);
  }
}

// ── 夹具 1：Hub-only（无直连样本，仅有 Hub 路径对端）──────────────────
fixture('hub-only: direct list empty but wg peer present, not conflated with empty network', () => {
  const wg = [{
    public_key: 'AbCdEfGh12345678…', endpoint: '198.51.100.7:51820',
    allowed_ips: '10.240.0.3/32', last_handshake: 0, rx_bytes: 0, tx_bytes: 0,
  }];
  const direct = directPeerRows([], T.zh, 'zh');
  const rows = wgPeerRows(wg, T.zh, 'zh');
  const sum = summarizePeers(wg);
  // 直连表空 ≠ 网络空：WG 表仍有该对端，endpoint 原样可见。
  assert.equal(direct.length, 0);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].endpoint, '198.51.100.7:51820');
  // 配置了对端但无握手：online 0 / total 1，不画成「空网络」。
  assert.deepEqual(sum, { online: 0, total: 1, rx: 0, tx: 0 });
});

// ── 夹具 2：P2P（有直连样本 + RTT 来源）───────────────────────────────
fixture('p2p: rows sorted newest-first, rtt value and source shown', () => {
  const direct = [
    { name: 'alpha', device_id: 'abcdef1234567890', virtual_ipv4: '10.240.0.3',
      endpoint: '203.0.113.9:4242', rtt_ms: 12.5, rtt_source: 'icmp', last_handshake_at: NOW - 30 },
    { name: 'beta', virtual_ipv4: '10.240.0.4', endpoint: '',
      rtt_ms: 3, rtt_source: 'ping', last_handshake_at: NOW - 10 },
  ];
  const rows = directPeerRows(direct, T.zh, 'zh');
  assert.equal(rows.length, 2);
  // 按最近握手新→旧排序：beta（NOW-10）在前。
  assert.equal(rows[0].name, 'beta');
  assert.equal(rows[1].name, 'alpha');
  const alpha = rows[1];
  assert.equal(alpha.rtt.chip, false);
  assert.equal(alpha.rtt.text, '12.5 ms');
  assert.equal(alpha.rtt.source, 'icmp');
  assert.equal(alpha.deviceShort, 'abcdef12');
  assert.equal(alpha.deviceFull, 'abcdef1234567890');
  assert.equal(alpha.vip, '10.240.0.3');
  assert.equal(alpha.endpoint, '203.0.113.9:4242');
  // 握手列是绝对时刻（clockOf），不是 '—'。
  assert.notEqual(alpha.stamp, '—');
});

// ── 夹具 3：无 RTT（直连在位但无样本）────────────────────────────────
fixture('no-rtt: missing rtt_ms renders as no-sample chip, not offline', () => {
  const direct = [
    { name: 'gamma', virtual_ipv4: '10.240.0.5', endpoint: '203.0.113.10:4242',
      rtt_ms: null, last_handshake_at: NOW - 5 },
    { name: 'delta', virtual_ipv4: '10.240.0.6', endpoint: '', last_handshake_at: NOW - 4 },
  ];
  for (const lang of ['zh', 'en']) {
    const rows = directPeerRows(direct, T[lang], lang);
    assert.equal(rows[0].rtt.chip, true);
    assert.equal(rows[0].rtt.text, T[lang].noSample);
    assert.equal(rows[0].rtt.source, '');
    // 字段整个缺失与 null 同判（undefined == null）。
    assert.equal(rows[1].rtt.chip, true);
    assert.equal(rows[1].rtt.text, T[lang].noSample);
  }
});

// ── 夹具 4：未握手（epoch 0 / 缺字段）────────────────────────────────
fixture('never-handshaked: wg shows never, direct stamp em-dash, online 0', () => {
  const wg = [{ public_key: 'k', endpoint: 'e', allowed_ips: 'a',
    last_handshake: 0, rx_bytes: 0, tx_bytes: 0 }];
  const rows = wgPeerRows(wg, T.zh, 'zh');
  assert.equal(rows[0].handshake, '从未');
  assert.equal(wgPeerRows(wg, T.en, 'en')[0].handshake, 'never');
  assert.deepEqual(summarizePeers(wg), { online: 0, total: 1, rx: 0, tx: 0 });
  const direct = directPeerRows([{ name: 'x' }], T.zh, 'zh');
  assert.equal(direct[0].stamp, '—');
  // 非法/负值 epoch 一律落「从未」，不产出 NaN 文案。
  assert.equal(fmtEpoch('garbage', 'zh', T.zh, NOW), '从未');
  assert.equal(fmtEpoch(-5, 'zh', T.zh, NOW), '从未');
  assert.equal(fmtEpoch(null, 'zh', T.zh, NOW), '从未');
});

// ── 夹具 5：旧快照（陈旧数据如实显旧，不臆造新鲜度）───────────────────
fixture('stale-snapshot: relative ages, absolute fallback, no fabricated vip', () => {
  // 2 小时前的握手按小时表达（zh/en）。
  assert.equal(fmtEpoch(NOW - 7200, 'zh', T.zh, NOW), '2 小时前');
  assert.equal(fmtEpoch(NOW - 7200, 'en', T.en, NOW), '2h ago');
  // 超过一天落绝对时间（2026-10-17 附近，含年份可查）。
  const old = fmtEpoch(NOW - 90 * 86400, 'zh', T.zh, NOW);
  assert.ok(old.includes('2026'), `absolute date with year, got: ${old}`);
  // status.updated_at 快照年龄（弹层旧口径：<1h 显秒、之后显分钟）。
  assert.equal(
    fmtUpdatedAt('2027-01-15T07:59:30Z', 'zh', T.zh, NOW_MS),
    '最后更新 30 秒前',
  );
  assert.equal(
    fmtUpdatedAt('2027-01-15T07:59:30Z', 'en', T.en, NOW_MS),
    'Updated 30s ago',
  );
  assert.equal(
    fmtUpdatedAt('2027-01-15T06:58:00Z', 'zh', T.zh, NOW_MS),
    '最后更新 62 分钟前',
  );
  assert.equal(
    fmtUpdatedAt('2027-01-15T06:58:00Z', 'en', T.en, NOW_MS),
    'Updated 62min ago',
  );
  // 缺失/坏 RFC3339 → 空串（页面如实省略年龄，不臆造「刚刚」）。
  assert.equal(fmtUpdatedAt(null, 'zh', T.zh, NOW_MS), '');
  assert.equal(fmtUpdatedAt('not-a-date', 'zh', T.zh, NOW_MS), '');
  // 旧/空诊断快照：无 meshlet/wg 接口 → 不臆造虚拟 IP、隧道不算在位。
  assert.equal(pickWgInterface([]), null);
  assert.equal(pickWgInterface(undefined), null);
  assert.equal(pickWgInterface([{ name: 'eth0', ipv4: '192.168.1.5', prefix: 24, state: 'up' }]), null);
  const wgIf = pickWgInterface([{ name: 'wg-meshlet', ipv4: '10.240.0.7', prefix: 16, state: 'up' }]);
  assert.equal(wgIf.ipv4, '10.240.0.7');
  assert.equal(wgIf.prefix, 16);
  assert.equal(isTunnelUp([]), false);
  assert.equal(isTunnelUp([{ name: 'eth0', state: 'up' }]), false);
  assert.equal(isTunnelUp([{ name: 'wg-meshlet', state: 'up' }]), true);
  // 直连表头快照时刻 = 最新握手的绝对时钟（数据多旧，时刻就多旧）。
  const direct = [{ name: 'a', last_handshake_at: NOW - 4000 }, { name: 'b', last_handshake_at: NOW - 100 }];
  assert.equal(newestHandshakeAt(direct, 'last_handshake_at'), NOW - 100);
});

// ── 夹具 6：读取失败（空/坏输入不炸、如实显空态）─────────────────────
fixture('read-failure: null/garbage inputs degrade to empty projections', () => {
  assert.deepEqual(directPeerRows(null, T.zh, 'zh'), []);
  assert.deepEqual(wgPeerRows(undefined, T.zh, 'zh'), []);
  assert.deepEqual(summarizePeers(null), { online: 0, total: 0, rx: 0, tx: 0 });
  assert.equal(newestHandshakeAt('garbage', 'last_handshake'), 0);
  // 空/未知状态落离线档（读取失败不猜在线）。
  assert.equal(tierOf(''), 'offline');
  assert.equal(tierOf(null), 'offline');
  assert.equal(tierOf('unknown'), 'offline');
});

// ── 附加钉：四档口径与 Rust state_tier 同表（state.rs tests 同夹具集）──
fixture('tier-of: parity table matches rust state_tier cases', () => {
  const cases = [
    ['Meshlet online', 'online'], ['Meshlet tunnel only', 'degraded'],
    ['Meshlet tunnel drift', 'degraded'], ['Meshlet offline', 'offline'],
    ['meshlet ONLINE', 'online'], ['MESHLET TUNNEL ONLY', 'degraded'],
    ['online', 'online'], ['tunnel_only', 'degraded'], ['tunnel_drift', 'degraded'],
    ['degraded', 'degraded'], ['error', 'error'], ['failed', 'error'],
    ['disconnected', 'offline'], ['down', 'offline'], ['unknown', 'offline'],
    ['setup', 'offline'], ['lookok', 'offline'],
  ];
  for (const [state, want] of cases) assert.equal(tierOf(state), want, state);
});

// ── 附加钉：zone 契约（字符串零改动，键集 = state.rs GOTO_ZONES）──────
fixture('zone-map: contract strings unchanged and targets valid', () => {
  const zones = ['conn', 'diag', 'cmd', 'gen', 'routes', 'ifaces', 'wg', 'peers'];
  assert.deepEqual(Object.keys(ZONE_MAP).sort(), [...zones].sort());
  const pages = ['connection', 'peers', 'diagnostics', 'general', 'commands'];
  const subs = { peers: ['direct', 'wg'], diagnostics: ['routes', 'interfaces', 'wireguard'] };
  for (const zone of zones) {
    const target = ZONE_MAP[zone];
    assert.equal(target.length >= 1 && target.length <= 2, true, zone);
    assert.ok(pages.includes(target[0]), `${zone} page ${target[0]}`);
    if (target[1]) assert.ok(subs[target[0]].includes(target[1]), `${zone} sub ${target[1]}`);
  }
  // 既有锚点语义逐条对照（旧入口定位一致）。
  assert.deepEqual(ZONE_MAP.conn, ['connection']);
  assert.deepEqual(ZONE_MAP.peers, ['peers', 'direct']);
  assert.deepEqual(ZONE_MAP.diag, ['diagnostics', 'routes']);
  assert.deepEqual(ZONE_MAP.routes, ['diagnostics', 'routes']);
  assert.deepEqual(ZONE_MAP.ifaces, ['diagnostics', 'interfaces']);
  assert.deepEqual(ZONE_MAP.wg, ['diagnostics', 'wireguard']);
  assert.deepEqual(ZONE_MAP.cmd, ['commands']);
  assert.deepEqual(ZONE_MAP.gen, ['general']);
});

// ── 附加钉：字节/时钟格式与旧入口同口径 ───────────────────────────────
fixture('formats: bytes units and clock fallback match legacy rendering', () => {
  assert.equal(fmtBytes(0), '0 B');
  assert.equal(fmtBytes(999), '999 B');
  assert.equal(fmtBytes(1024), '1.0 KB');
  assert.equal(fmtBytes(1048576), '1.0 MB');
  assert.equal(fmtBytes(1073741824), '1.00 GB');
  assert.equal(fmtBytes(null), '0 B');
  assert.equal(fmtBytes('2048'), '2.0 KB');
  assert.equal(clockOf(0, 'zh'), '—');
  assert.equal(clockOf(null, 'en'), '—');
  assert.notEqual(clockOf(NOW, 'zh'), '—');
});

// ── 收尾 ─────────────────────────────────────────────────────────────
console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
  console.error(`failed fixtures: ${failures.join(', ')}`);
  process.exit(1);
}
