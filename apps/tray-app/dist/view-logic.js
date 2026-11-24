// 设置窗/弹层共用纯展示逻辑（无 DOM、无 IPC 依赖）。抽出的目的：
// 1) index.html 与 popup.html 单一来源，不再各抄一份口径（tierOf 三处
//    拷贝曾因 last_handshake 从「N 秒前」字符串迁 raw epoch 而 drift——
//    popup 仍按字符串解析，握手列显示成天文数字秒）；
// 2) node 夹具测试直接 import（tests/view-fixtures.mjs），六种夹具
//    （Hub-only / P2P / 无 RTT / 未握手 / 旧快照 / 读取失败）在无
//    Windows 真机的环境下钉住显示语义。
// 同步约定：本文件改动后须逐字节同步到 dist/（与 index.html 同规）。

// ── 状态四档（口径 = src-tauri/src/state.rs state_tier）───────────────
// 真实生产者是 agent accessible_name() 全称句（"Meshlet online" 等），
// 小写化后按子串匹配；判定顺序固定：降级 → 异常 → 在线 → 离线。
// snake_case（online/tunnel_only/error…）继续兼容防回归。
export function tierOf(state) {
  const s = String(state || '').toLowerCase();
  if (s.includes('tunnel only') || s.includes('tunnel_only') || s.includes('tunnel drift') ||
      s.includes('tunnel_drift') || s.includes('degraded')) return 'degraded';
  if (s.includes('error') || s.includes('failed')) return 'error';
  if (s.includes('online') || ['connected', 'ready', 'up', 'ok'].includes(s)) return 'online';
  return 'offline';
}

// ── 数值/时间格式（弹层与设置窗同口径）────────────────────────────────
export function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
  return (n / 1073741824).toFixed(2) + ' GB';
}

// epoch 秒 → 「N 秒/分钟/小时前」，超过一天落绝对时间（哪一天可查）。
export function fmtEpoch(epoch, lang, t, nowSecs) {
  const value = Number(epoch);
  if (!(value > 0)) return t.never;
  const secs = Math.max(0, Math.floor((nowSecs ?? Date.now() / 1000) - value));
  if (secs < 60) return lang === 'zh' ? `${secs} 秒前` : `${secs}s ago`;
  if (secs < 3600) return lang === 'zh' ? `${Math.floor(secs / 60)} 分钟前` : `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return lang === 'zh' ? `${Math.floor(secs / 3600)} 小时前` : `${Math.floor(secs / 3600)}h ago`;
  try { return new Date(value * 1000).toLocaleString(lang === 'zh' ? 'zh-CN' : 'en-US'); }
  catch (_) { return '—'; }
}

// epoch 秒 → 当地时钟（表格里「最近握手」的绝对时刻列）；无样本显 —。
export function clockOf(epoch, lang) {
  const value = Number(epoch);
  if (!(value > 0)) return '—';
  try { return new Date(value * 1000).toLocaleTimeString(lang === 'zh' ? 'zh-CN' : 'en-US'); }
  catch (_) { return '—'; }
}

// status.updated_at（RFC3339）→「最后更新 N 前」。弹层旧入口同口径；
// 缺失/解析失败返回空串（调用方如实省略，不臆造新鲜度）。
export function fmtUpdatedAt(rfc3339, lang, t, nowMs) {
  if (!rfc3339) return '';
  const ms = Date.parse(rfc3339);
  if (!Number.isFinite(ms)) return '';
  const secs = Math.max(0, Math.round(((nowMs ?? Date.now()) - ms) / 1000));
  const label = lang === 'zh' ? `${secs} 秒前` : `${secs}s ago`;
  if (secs < 3600) return `${t.lastUpdate} ${label}`;
  const mins = Math.round(secs / 60);
  return `${t.lastUpdate} ${lang === 'zh' ? `${mins} 分钟前` : `${mins}min ago`}`;
}

// ── 诊断快照投影（设置窗状态条与弹层隧道行共用）───────────────────────
// 只认 meshlet/wg 命名且带 IPv4 的接口；旧快照/无隧道 → null（显示 —，
// 不臆造虚拟 IP）。
export function pickWgInterface(interfaces) {
  return (Array.isArray(interfaces) ? interfaces : [])
    .find((i) => /meshlet|wg/i.test(i?.name || '') && i.ipv4) || null;
}

// 隧道是否在位：meshlet/wg 命名接口 state === 'up'（弹层「隧道状态」行）。
export function isTunnelUp(interfaces) {
  return (Array.isArray(interfaces) ? interfaces : [])
    .some((i) => /meshlet|wg/i.test(i?.name || '') && i.state === 'up');
}

// ── 对等节点表投影（六种夹具钉语义）───────────────────────────────────
// 汇总：online 按 connected 布尔（state.rs 按握手新鲜度 <180s 判定）。
export function summarizePeers(peers) {
  const list = Array.isArray(peers) ? peers : [];
  let online = 0;
  let rx = 0;
  let tx = 0;
  for (const p of list) {
    if (p?.connected) online += 1;
    rx += Number(p?.rx_bytes) || 0;
    tx += Number(p?.tx_bytes) || 0;
  }
  return { online, total: list.length, rx, tx };
}

// 指定字段的最大非零 epoch（=最近一次握手）；全无样本返回 0。
export function newestHandshakeAt(peers, field) {
  const list = Array.isArray(peers) ? peers : [];
  let newest = 0;
  for (const p of list) {
    const value = Number(p?.[field]) || 0;
    if (value > newest) newest = value;
  }
  return newest;
}

// P2P 直连表行投影：按最近握手新→旧排序；rtt_ms 缺失=「无样本」chip
// （无样本 ≠ 离线，其余观测照常展示）。返回纯数据，页面负责转义与排版。
export function directPeerRows(peers, t, lang) {
  const list = Array.isArray(peers) ? peers : [];
  return [...list]
    .sort((a, b) => (Number(b?.last_handshake_at) || 0) - (Number(a?.last_handshake_at) || 0))
    .map((p) => ({
      name: p?.name ?? '',
      deviceShort: p?.device_id ? String(p.device_id).slice(0, 8) : '',
      deviceFull: p?.device_id || '',
      vip: p?.virtual_ipv4 || '',
      endpoint: p?.endpoint || '',
      rtt: p?.rtt_ms == null
        ? { chip: true, text: t.noSample, source: '' }
        : { chip: false, text: `${p.rtt_ms} ${t.unitMs}`, source: p?.rtt_source || '' },
      stamp: clockOf(p?.last_handshake_at, lang),
    }));
}

// WireGuard 对端表行投影：按最近握手新→旧排序；未握手（epoch 0/缺）显
// 「从未」。返回纯数据，页面负责转义与排版。
export function wgPeerRows(peers, t, lang) {
  const list = Array.isArray(peers) ? peers : [];
  return [...list]
    .sort((a, b) => (Number(b?.last_handshake) || 0) - (Number(a?.last_handshake) || 0))
    .map((p) => ({
      key: p?.public_key || '',
      allowed: p?.allowed_ips || '',
      endpoint: p?.endpoint || '',
      handshake: fmtEpoch(p?.last_handshake, lang, t),
      traffic: `${fmtBytes(p?.rx_bytes)} / ${fmtBytes(p?.tx_bytes)}`,
    }));
}

// ── 深链定位（zone 契约，字符串零改动）───────────────────────────────
// 既有 zone 契约（state.rs GOTO_ZONES）映射到新五页结构：
//  conn → 连接；peers → 对等节点(P2P tab)；
//  diag → 诊断(路由 tab)；routes/ifaces/wg → 诊断对应 tab；
//  cmd → 命令参考；gen → 常规。
export const ZONE_MAP = {
  conn: ['connection'],
  peers: ['peers', 'direct'],
  diag: ['diagnostics', 'routes'],
  routes: ['diagnostics', 'routes'],
  ifaces: ['diagnostics', 'interfaces'],
  wg: ['diagnostics', 'wireguard'],
  cmd: ['commands'],
  gen: ['general'],
};
