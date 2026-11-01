#!/usr/bin/env bash
# DOC-GIF 流水线：真实验证配置开关效果，产出 off/on 截图 + GIF（docs/public/toggles/）。
# 兼作配置效果回归测试：capture.mjs 任一断言失败即非零退出。
#
# 用法：
#   scripts/doc-gif/run.sh            # 构建产物 + 起临时 server + 捕获 + 合成 GIF
#   SKIP_BUILD=1 scripts/doc-gif/run.sh   # 跳过 console/二进制重建
#
# 输出：
#   docs/public/toggles/console-theme-off.png|on.png|.gif
#   docs/public/toggles/console-lang-en.png|zh.png|.gif
#   docs/public/toggles/cookie-secure-off.png|on.png|.gif
#   docs/public/toggles/console-served-off.png|on.png|.gif
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"

SERVER_BIN="$REPO/target/debug/meshlet-server"
CONSOLE_DIST="$REPO/console/dist"
SCRATCH="$HERE/scratch"
OUT="$REPO/docs/public/toggles"

EMAIL="${MESHLET_DOCGIF_EMAIL:-admin@docgif.local}"
PASSWORD="${MESHLET_DOCGIF_PASSWORD:-docgif-admin-2026-pass}"

# 端口：避免与系统 server（18080）和无关进程冲突。
CONSOLE_PORT="${MESHLET_DOCGIF_CONSOLE_PORT:-18082}"
COOKIE_PORT="${MESHLET_DOCGIF_COOKIE_PORT:-18083}"
NOCONSOLE_PORT="${MESHLET_DOCGIF_NOCONSOLE_PORT:-18084}"

pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

log() { echo "[doc-gif] $*"; }

# ---------------------------------------------------------------------------
# 构建（可重跑；配置/源码变更后重生成证据）
# ---------------------------------------------------------------------------
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  log "building console dist"
  (cd console && pnpm build)
  log "building meshlet-server binary"
  cargo build --bin meshlet-server
else
  log "SKIP_BUILD=1, reusing existing dist + binary"
fi
[ -f "$SERVER_BIN" ] || { echo "missing $SERVER_BIN; run without SKIP_BUILD" >&2; exit 1; }
[ -d "$CONSOLE_DIST" ] || { echo "missing $CONSOLE_DIST; run without SKIP_BUILD" >&2; exit 1; }

mkdir -p "$SCRATCH" "$OUT"
rm -f "$SCRATCH"/*.db "$SCRATCH"/*.db-* "$SCRATCH"/server-*.log
rm -rf "$HERE/frames"

# ---------------------------------------------------------------------------
# 起临时 server 实例（全隔离：临时 DB、临时端口、本机回环）
# ---------------------------------------------------------------------------
start_server() {
  local name="$1" port="$2" db="$3" console_dir="$4" cookie_secure="$5"
  local toml="$SCRATCH/$name.toml"
  {
    echo "bind = \"127.0.0.1:$port\""
    echo "database_path = \"$db\""
    echo "cookie_secure = $cookie_secure"
    [ -n "$console_dir" ] && echo "console_dir = \"$console_dir\""
  } > "$toml"
  "$SERVER_BIN" "$toml" > "$SCRATCH/server-$name.log" 2>&1 &
  pids+=($!)
  for _ in $(seq 1 60); do
    if curl -sf -o /dev/null "http://127.0.0.1:$port/api/v1/system/status"; then
      log "server $name up on :$port"
      return 0
    fi
    sleep 0.5
  done
  echo "server $name failed to start; log:" >&2
  tail -20 "$SCRATCH/server-$name.log" >&2
  exit 1
}

start_server console  "$CONSOLE_PORT" "$SCRATCH/console.db" "$CONSOLE_DIST" "false"
start_server cookie   "$COOKIE_PORT"  "$SCRATCH/cookie.db"  "" "true"
start_server noconsole "$NOCONSOLE_PORT" "$SCRATCH/noconsole.db" "" "false"

# ---------------------------------------------------------------------------
# 捕获 + 断言 + GIF 合成
# ---------------------------------------------------------------------------
export MESHLET_DOCGIF_EMAIL="$EMAIL" MESHLET_DOCGIF_PASSWORD="$PASSWORD"
export MESHLET_DOCGIF_CONSOLE_BASE="http://127.0.0.1:$CONSOLE_PORT"
export MESHLET_DOCGIF_COOKIE_BASE="http://127.0.0.1:$COOKIE_PORT"
export MESHLET_DOCGIF_NOCONSOLE_BASE="http://127.0.0.1:$NOCONSOLE_PORT"
export MESHLET_DOCGIF_OUT="$OUT"

if [ -f "$HERE/pnpm-lock.yaml" ]; then
  (cd "$HERE" && pnpm install --frozen-lockfile)
else
  (cd "$HERE" && pnpm install)
fi
(cd "$HERE" && node capture.mjs)

log "done. outputs in $OUT"
