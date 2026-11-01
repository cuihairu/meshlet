// DOC-GIF 捕获：真实 UI / 真实 HTTP 输出 → off/on 截图 + 过渡帧 → ffmpeg 合成 GIF。
// 兼作配置效果回归测试：任一断言失败即以非零退出码退出（可进 CI 门禁）。
//
// 被捕获的开关（见 docs 配置效果页）：
//   1. console 主题（dark↔light）         —— 真实 antd 切换，断言 html[data-theme]
//   2. console 语言（en↔zh）              —— 真实 antd Dropdown，断言导航文本 + localStorage
//   3. server cookie_secure（false→true） —— 真实 bootstrap Set-Cookie，断言 Secure 属性出现
//   4. server console_dir（未设→已设）     —— 真实 GET /，断言 404→200
//
// 依赖：playwright（chromium，见 package.json）、ffmpeg（合成 GIF）、
//       run.sh 预先起的临时 meshlet-server 实例。
import { chromium } from 'playwright';
import { execFileSync } from 'node:child_process';
import { readdirSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FRAMES = path.join(__dirname, 'frames');

const CONSOLE_BASE = process.env.MESHLET_DOCGIF_CONSOLE_BASE || 'http://127.0.0.1:18082';
const COOKIE_BASE = process.env.MESHLET_DOCGIF_COOKIE_BASE || 'http://127.0.0.1:18083';
const NOCONSOLE_BASE = process.env.MESHLET_DOCGIF_NOCONSOLE_BASE || 'http://127.0.0.1:18084';
const OUT = process.env.MESHLET_DOCGIF_OUT || path.resolve(__dirname, '../../docs/public/toggles');
const EMAIL = process.env.MESHLET_DOCGIF_EMAIL || 'admin@docgif.local';
const PASSWORD = process.env.MESHLET_DOCGIF_PASSWORD || 'docgif-admin-2026-pass';

const VIEWPORT = { width: 1280, height: 800 };
const TERM_FPS = 6;
const UI_FPS = 8;

let failures = 0;
const check = (name, cond, detail = '') => {
  if (cond) console.log(`  ok  ${name}`);
  else { failures += 1; console.error(`  FAIL ${name} ${detail}`); }
};

// ---------------------------------------------------------------------------
// GIF 合成（palettegen/paletteuse，避免色彩抖动）
// ---------------------------------------------------------------------------
function gifFromFrames(dir, out, fps) {
  const frames = readdirSync(dir).filter((f) => f.endsWith('.png')).sort();
  if (frames.length === 0) throw new Error(`no frames in ${dir}`);
  const palette = path.join(dir, 'palette.png');
  const pat = path.join(dir, 'frame_%03d.png');
  execFileSync('ffmpeg', ['-y', '-framerate', String(fps), '-i', pat, '-vf', 'palettegen', '-loglevel', 'error', palette]);
  execFileSync('ffmpeg', ['-y', '-framerate', String(fps), '-i', pat, '-i', palette, '-lavfi', 'paletteuse', '-loglevel', 'error', out]);
}

function freshFrames(name) {
  const dir = path.join(FRAMES, name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  return dir;
}

async function shotFrames(page, dir, count, pauseMs, start = 0) {
  for (let i = 0; i < count; i += 1) {
    const n = start + i;
    await page.screenshot({ path: path.join(dir, `frame_${String(n).padStart(3, '0')}.png`) });
    if (pauseMs) await page.waitForTimeout(pauseMs);
  }
}

// 当前导航链接文本（用于语言状态自检，避免缓存/竞态把错帧写进 GIF）。
async function navText(page) {
  const el = page.locator('a[href="#/networks"]').first();
  if ((await el.count()) === 0) return null;
  return (await el.textContent())?.trim();
}

// ---------------------------------------------------------------------------
// 终端渲染（真实捕获文本 → 终端风格帧）
// ---------------------------------------------------------------------------
function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function terminalHtml(title, lines) {
  const body = lines
    .map((l) => {
      const cls = l.c ? ` class="${l.c}"` : '';
      return `<span${cls}>${esc(l.t)}</span>`;
    })
    .join('\n');
  return `<!doctype html><html><head><meta charset="utf-8"><style>
    *{box-sizing:border-box} html,body{margin:0;background:#0b0f14}
    body{padding:24px;font-family:'DejaVu Sans Mono',monospace}
    .term{width:920px;background:#0b0f14;border:1px solid #2a3440;border-radius:8px;overflow:hidden}
    .bar{background:#161c24;padding:9px 12px;display:flex;gap:6px;align-items:center}
    .dot{width:11px;height:11px;border-radius:50%}
    .r{background:#ff5f57}.y{background:#febc2e}.g{background:#28c840}
    .title{color:#8b98a5;font-size:13px;margin-left:8px}
    .body{margin:0;padding:14px 16px;white-space:pre-wrap;color:#e6edf3;font-size:13px;line-height:1.6}
    .cmd{color:#22c55e}.head{color:#7ee787}.dim{color:#8b98a5}.hi{color:#ffd479}
  </style></head><body><div class="term"><div class="bar">
    <span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
    <span class="title">${esc(title)}</span></div>
    <pre class="body">${body}</pre></div></body></html>`;
}

// 逐行揭示 → 帧（模拟终端输出逐行出现）
async function terminalFrames(page, title, lines, dir) {
  for (let n = 1; n <= lines.length; n += 1) {
    await page.setContent(terminalHtml(title, lines.slice(0, n)));
    await page.waitForTimeout(90);
    await page.screenshot({ path: path.join(dir, `frame_${String(n - 1).padStart(3, '0')}.png`) });
  }
}

async function terminalShot(page, title, lines, out) {
  await page.setContent(terminalHtml(title, lines));
  await page.waitForTimeout(150);
  await page.screenshot({ path: out });
}

// ---------------------------------------------------------------------------
// 真实 HTTP 捕获（fetch 直连临时 server）
// ---------------------------------------------------------------------------
async function httpRequest(base, method, urlPath, body) {
  const res = await fetch(base + urlPath, {
    method,
    headers: body ? { 'content-type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const setCookie = res.headers.get('set-cookie') || '';
  const ct = res.headers.get('content-type') || '';
  const text = await res.text();
  return { status: res.status, setCookie, ct, text };
}

function shortToken(cookie) {
  // 仅展示真实 cookie 头，token 值缩短以便阅读（不影响 Secure 属性可见性）。
  return cookie.replace(/meshlet_session=[^;]+/, (m) => `${m.slice(0, 34)}…`);
}

// ---------------------------------------------------------------------------
// console 捕获
// ---------------------------------------------------------------------------
async function captureConsole(page) {
  // 管理员已由 captureCookieSecure 的首次 bootstrap 创建（CONSOLE_BASE）。
  // 真实 UI 登录（antd 表单）。
  await page.goto(`${CONSOLE_BASE}/`, { waitUntil: 'networkidle' });
  await page.getByLabel('Email').waitFor({ timeout: 15000 });
  await page.getByLabel('Email').fill(EMAIL);
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('link', { name: 'Networks', exact: true }).waitFor({ timeout: 15000 });
  check('console signed in (nav visible)', true);

  // --- 主题：dark（off）↔ light（on）---
  await page.evaluate(() => localStorage.setItem('meshlet-theme', 'dark'));
  await page.reload({ waitUntil: 'networkidle' });
  await page.locator('html[data-theme="dark"]').waitFor({ timeout: 10000 });
  await page.screenshot({ path: path.join(OUT, 'console-theme-off.png') });

  const themeToggle = page.locator('button[aria-label$="theme"]');
  const themeFrames = freshFrames('theme');
  await themeToggle.click();
  await shotFrames(page, themeFrames, 10, 120);
  await page.locator('html[data-theme="light"]').waitFor({ timeout: 5000 });
  await page.screenshot({ path: path.join(OUT, 'console-theme-on.png') });

  const theme = await page.locator('html').getAttribute('data-theme');
  const themeStored = await page.evaluate(() => localStorage.getItem('meshlet-theme'));
  check('theme flips to light', theme === 'light', `got ${theme}`);
  check('theme persists', themeStored === 'light', `got ${themeStored}`);
  gifFromFrames(themeFrames, path.join(OUT, 'console-theme.gif'), UI_FPS);

  // --- 语言：en（off）↔ zh（on）---
  await page.evaluate(() => localStorage.setItem('meshlet-lang', 'en'));
  await page.reload({ waitUntil: 'networkidle' });
  await page.getByRole('link', { name: 'Networks', exact: true }).waitFor({ timeout: 10000 });
  check('lang reload renders EN', (await navText(page)) === 'Networks', `nav=${await navText(page)}`);
  await page.screenshot({ path: path.join(OUT, 'console-lang-en.png') });

  const langFrames = freshFrames('lang');
  await page.getByRole('button', { name: 'Change language' }).click();
  await page.getByRole('menuitem', { name: '中文' }).waitFor({ timeout: 5000 });
  // 下拉展开阶段（此时仍为英文）——真实开合动画帧。
  await shotFrames(page, langFrames, 3, 100, 0);
  check('dropdown open still EN', (await navText(page)) === 'Networks', `nav=${await navText(page)}`);
  // 选择中文 → 全站重渲染。
  await page.getByRole('menuitem', { name: '中文' }).click();
  await page.getByRole('link', { name: '网络', exact: true }).waitFor({ timeout: 10000 });
  await shotFrames(page, langFrames, 6, 110, 3);
  await page.screenshot({ path: path.join(OUT, 'console-lang-zh.png') });

  const langStored = await page.evaluate(() => localStorage.getItem('meshlet-lang'));
  check('language flips to zh nav', (await page.getByRole('link', { name: '网络', exact: true }).count()) === 1);
  check('language persists', langStored === 'zh', `got ${langStored}`);
  gifFromFrames(langFrames, path.join(OUT, 'console-lang.gif'), UI_FPS);
}

// ---------------------------------------------------------------------------
// cookie_secure 捕获（真实 bootstrap Set-Cookie）
// ---------------------------------------------------------------------------
async function captureCookieSecure(page) {
  // 首个 bootstrap 也顺带创建 CONSOLE_BASE 管理员（供 UI 登录）。
  const off = await httpRequest(CONSOLE_BASE, 'POST', '/api/v1/auth/bootstrap', { email: EMAIL, password: PASSWORD });
  const on = await httpRequest(COOKIE_BASE, 'POST', '/api/v1/auth/bootstrap', { email: EMAIL, password: PASSWORD });
  check('cookie_secure off bootstrap is 201', off.status === 201, `status=${off.status}`);

  const cmd = `$ curl -i -s -X POST ${CONSOLE_BASE}/api/v1/auth/bootstrap -H 'content-type: application/json' -d '{"email":"${EMAIL}","password":"***"}'`;
  const offLines = [
    { t: cmd, c: 'cmd' },
    { t: 'HTTP/1.1 201 Created', c: 'head' },
    { t: `set-cookie: ${shortToken(off.setCookie)}`, c: 'dim' },
    { t: '{"user_id":"…","email":"admin@docgif.local","two_factor_required":false}', c: '' },
  ];
  const onLines = [
    { t: cmd.replace(CONSOLE_BASE, COOKIE_BASE), c: 'cmd' },
    { t: 'HTTP/1.1 201 Created', c: 'head' },
    { t: `set-cookie: ${shortToken(on.setCookie)}`, c: 'hi' },
    { t: '{"user_id":"…","email":"admin@docgif.local","two_factor_required":false}', c: '' },
  ];

  const offSecure = off.setCookie.includes('; Secure');
  const onSecure = on.setCookie.includes('; Secure');
  check('cookie_secure off: no Secure attr', !offSecure);
  check('cookie_secure on: Secure attr present', onSecure, `cookie=${on.setCookie}`);

  const page2 = await page.context().newPage();
  await terminalShot(page2, 'meshlet-server cookie_secure=false', offLines, path.join(OUT, 'cookie-secure-off.png'));
  await terminalShot(page2, 'meshlet-server cookie_secure=true', onLines, path.join(OUT, 'cookie-secure-on.png'));
  const dir = freshFrames('cookie-secure');
  await terminalFrames(page2, 'cookie_secure: off → on', [...offLines, { t: '…', c: 'dim' }, ...onLines], dir);
  gifFromFrames(dir, path.join(OUT, 'cookie-secure.gif'), TERM_FPS);
  await page2.close();
}

// ---------------------------------------------------------------------------
// console_dir 捕获（真实 GET /）
// ---------------------------------------------------------------------------
async function captureConsoleServed(page) {
  const on = await httpRequest(CONSOLE_BASE, 'GET', '/');
  const off = await httpRequest(NOCONSOLE_BASE, 'GET', '/');

  check('console_dir set: GET / is 200', on.status === 200, `status=${on.status}`);
  check('console_dir unset: GET / is 404', off.status === 404, `status=${off.status}`);

  const offLines = [
    { t: `$ curl -i -s ${NOCONSOLE_BASE}/`, c: 'cmd' },
    { t: 'HTTP/1.1 404 Not Found', c: 'head' },
    { t: `content-type: ${off.ct || '(empty)'}`, c: 'dim' },
    ...(off.text.trim() ? [{ t: off.text.trim().slice(0, 40), c: '' }] : []),
  ];
  const onLines = [
    { t: `$ curl -i -s ${CONSOLE_BASE}/`, c: 'cmd' },
    { t: 'HTTP/1.1 200 OK', c: 'head' },
    { t: `content-type: ${on.ct || '(empty)'}`, c: 'dim' },
    { t: on.text.trim().slice(0, 40), c: '' },
  ];

  const page2 = await page.context().newPage();
  await terminalShot(page2, 'console_dir unset', offLines, path.join(OUT, 'console-served-off.png'));
  await terminalShot(page2, 'console_dir = console/dist', onLines, path.join(OUT, 'console-served-on.png'));
  const dir = freshFrames('console-served');
  await terminalFrames(page2, 'console_dir: 未设置 → 已设置', [...offLines, { t: '…', c: 'dim' }, ...onLines], dir);
  gifFromFrames(dir, path.join(OUT, 'console-served.gif'), TERM_FPS);
  await page2.close();
}

// ---------------------------------------------------------------------------
async function main() {
  mkdirSync(OUT, { recursive: true });
  rmSync(FRAMES, { recursive: true, force: true });

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: VIEWPORT });
  const page = await context.newPage();

  console.log('[capture] server cookie_secure');
  await captureCookieSecure(page);
  console.log('[capture] console theme + language');
  await captureConsole(page);
  console.log('[capture] server console_dir');
  await captureConsoleServed(page);

  await browser.close();

  console.log(failures === 0 ? '[capture] all checks passed' : `[capture] ${failures} check(s) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('[capture] fatal:', err);
  process.exit(1);
});
