# DOC-GIF capture pipeline

Reproducible evidence for the docs [配置效果 (toggle effects)](../../docs/guide/toggles.md)
page: every recorded toggle gets an off/on screenshot plus an animated GIF, and the
script doubles as a regression test.

## What it captures

| Toggle | Effect observed | Evidence |
| --- | --- | --- |
| Console theme (dark ↔ light) | `html[data-theme]` flips, `localStorage['meshlet-theme']` persists | real antd switch, headless Chromium |
| Console language (en ↔ zh) | nav labels + `localStorage['meshlet-lang']` flip | real antd Dropdown, headless Chromium |
| Server `cookie_secure` | `Set-Cookie` gains `Secure` | real HTTP bootstrap response |
| Server `console_dir` | `GET /` goes 404 → 200 | real HTTP response |

Toggles whose effect needs a host this script cannot drive (tray app, agent data
plane, P2P direct peers) are listed in the docs page as not-yet-recordable rather
than faked.

## Usage

```sh
scripts/doc-gif/run.sh            # build console + server, capture, assert, write images
SKIP_BUILD=1 scripts/doc-gif/run.sh   # reuse existing dist + binary (faster)
```

Outputs land in `docs/public/toggles/` and are committed. The script exits non-zero
if any effect assertion fails, so a configuration change that breaks an effect
surfaces as a failing run.

## Requirements

- Linux with `cargo` (Rust), `pnpm`, and `ffmpeg` on PATH.
- Playwright browser already present at `~/.cache/ms-playwright` (or run
  `pnpm exec playwright install chromium` once).
- Loopback ports 18082–18084 free (system server and unrelated processes are never
  touched; the script uses its own throwaway configs and databases).

## Notes

- Server instances, databases, and frames are created under `scratch/` and `frames/`
  (gitignored) and rebuilt on every run, so the run is deterministic.
- Console captures require a signed-in session; the script bootstraps a throwaway
  admin on the console server first.
