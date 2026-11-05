#!/usr/bin/env bash
# Offline (Linux) validation of apps/cli/wix/main.wxs via wixl (msitools).
#
# cargo-wix runs only on Windows CI, so this script is the fast pre-merge gate:
# 1. existence-check every non-variable Source/SourceFile in the wxs against
#    the repo root (backslashes normalized to forward slashes);
# 2. dry-run wixl with $(var.Cargo*) defines stubbed out (dummy exe files),
#    producing a real msi whose File/Shortcut tables are then inspected.
#
# wixl is a WiX subset: it does not understand a backslash separator after a
# substituted variable define ($(var.CargoTargetBinDir)\name.exe), so the
# variable is rewritten to a forward-slash stub directory for the dry run.
# The committed wxs keeps the backslash form that the real cargo-wix run
# injects on Windows.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
wxs="$root/apps/cli/wix/main.wxs"
stub=$(mktemp -d)
trap 'rm -rf "$stub"' EXIT

# --- 1. non-variable Source existence check -------------------------------
python3 - "$root" "$wxs" <<'PY'
import re, sys, os.path

root, wxs = sys.argv[1], sys.argv[2]
text = open(wxs).read()
srcs = re.findall(r'(?:Source|SourceFile)=[\'"]([^"\']+)[\'"]', text)
scanned = missing = 0
for src in srcs:
    if "$(" in src:
        continue  # variable source: cargo-wix injects it at packaging time
    scanned += 1
    path = os.path.join(root, src.replace("\\", "/"))
    if not os.path.exists(path):
        print(f"MISSING wxs source: {src} -> {path}")
        missing += 1
print(f"wxs sources scanned (non-variable)={scanned} missing={missing}")
if missing:
    sys.exit(1)
if scanned == 0:
    print("no non-variable sources found; check the regex")
    sys.exit(1)
PY

# --- 2. wixl dry run -------------------------------------------------------
mkdir -p "$stub/bin"
for exe in meshlet-server meshlet-agent meshlet-cli meshlet-tray-host; do
    : > "$stub/bin/$exe.exe"
done
version=$(python3 - <<'PY'
import re
text = open("Cargo.toml").read()
print(re.search(r'\[workspace\.package\][^[]*?version\s*=\s*"([^"]+)"', text, re.S).group(1))
PY
)
sed "s|\$(var.CargoTargetBinDir)\\\\|$stub/bin/|g" "$wxs" > "$stub/main.wxs"

wixl -a x64 -D "CargoPackageVersion=$version" -o "$stub/out.msi" "$stub/main.wxs"

# --- 3. inspect the produced msi -------------------------------------------
files=$(msiinfo export "$stub/out.msi" File | awk -F '\t' 'NR>2 {print $3}' | sort | tr '\n' ' ')
shortcuts=$(msiinfo export "$stub/out.msi" Shortcut | awk -F '\t' 'NR>2 {print $3}' | sort | tr '\n' ' ')
version_msi=$(msiinfo export "$stub/out.msi" Property | awk -F '\t' '$1=="ProductVersion" {print $2}' | tr -d '\r')
echo "msi File table:   $files"
echo "msi Shortcut tab: $shortcuts"
echo "msi version:      $version_msi (workspace $version)"

for exe in meshlet-server.exe meshlet-agent.exe meshlet-cli.exe meshlet-tray-host.exe; do
    case " $files " in
        *" $exe "*) ;;
        *) echo "msi File table is missing $exe"; exit 1 ;;
    esac
done
for sc in "Meshlet CLI" "Meshlet Tray Host" "Uninstall Meshlet"; do
    case " $shortcuts " in
        *" $sc "*) ;;
        *) echo "msi Shortcut table is missing '$sc'"; exit 1 ;;
    esac
done
if [ "$version_msi" != "$version" ]; then
    echo "msi version $version_msi != workspace version $version"
    exit 1
fi
echo "wix validation OK"
