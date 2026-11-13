#!/bin/sh
# Builds the three OpenWrt .ipk packages for meshlet (custos precedent):
#   meshlet             musl static binaries (server+agent+cli) + procd inits
#                       + UCI config, arch-specific
#   luci-app-meshlet    LuCI controller, settings page and status dashboard
#                       (arch all)
#   app-meta-meshlet    iStore app metadata (icon + app json), arch all
#
# Usage: build-ipk.sh <bin-dir> [out-dir] [--arch x86_64|aarch64] [--rel N]
#
# <bin-dir> must contain the release binaries meshlet-server, meshlet-agent
# and meshlet-cli (e.g. target/x86_64-unknown-linux-musl/release). The
# package architecture is derived from the server ELF (`file`); --arch
# overrides it. The .ipk container is the tar.gz layout (debian-binary +
# control.tar.gz + data.tar.gz as a single tar), the same form the custos
# package ships and which opkg on iStoreOS 24.10 installs.
set -eu

die() { printf 'build-ipk: %s\n' "$*" >&2; exit 1; }

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SRC="$SCRIPT_DIR"
REPO_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)

BINDIR=""
OUT="."
ARCH_OVERRIDE=""
REL_OVERRIDE=""
while [ $# -gt 0 ]; do
	case "$1" in
		--rel)
			[ $# -ge 2 ] || die "--rel requires a value"
			REL_OVERRIDE="$2"
			shift 2
			;;
		--arch)
			[ $# -ge 2 ] || die "--arch requires a value (x86_64|aarch64)"
			ARCH_OVERRIDE="$2"
			shift 2
			;;
		--*)
			die "unknown option: $1"
			;;
		*)
			if [ -z "$BINDIR" ]; then
				BINDIR="$1"
			else
				OUT="$1"
			fi
			shift
			;;
	esac
done

[ -n "$BINDIR" ] || die "usage: build-ipk.sh <bin-dir> [out-dir] [--arch x86_64|aarch64] [--rel N]"
[ -d "$BINDIR" ] || die "bin dir not found: $BINDIR"
for b in meshlet-server meshlet-agent meshlet-cli; do
	[ -f "$BINDIR/$b" ] || die "missing binary in $BINDIR: $b"
done
[ -f "$SRC/app-meta/meshlet.json" ] || die "app-meta/meshlet.json missing"
[ -f "$REPO_DIR/assets/icons/meshlet.png" ] || die "assets/icons/meshlet.png missing"

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO_DIR/Cargo.toml" | head -1)
[ -n "$VERSION" ] || die "cannot read version from Cargo.toml"
REL="${VERSION}-1"
[ -n "$REL_OVERRIDE" ] && REL="${VERSION}-${REL_OVERRIDE}"

if [ -n "$ARCH_OVERRIDE" ]; then
	case "$ARCH_OVERRIDE" in
		x86_64 | aarch64) ARCH="$ARCH_OVERRIDE" ;;
		*) die "unsupported --arch: $ARCH_OVERRIDE (expected x86_64|aarch64)" ;;
	esac
else
	# `file` reports the ELF machine, mapped to opkg's architecture names.
	ARCH=$(file -b "$BINDIR/meshlet-server" | sed -n 's/.*[, ]\(x86-64\|aarch64\).*/\1/p' | head -1)
	case "$ARCH" in
		x86-64) ARCH=x86_64 ;;
		aarch64) ARCH=aarch64 ;;
		*) die "unsupported binary architecture: $ARCH (pass --arch)" ;;
	esac
fi

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

# ---- meshlet (arch-specific) ----------------------------------------------
R="$STAGE/meshlet"
mkdir -p "$R/data/etc/init.d" "$R/data/etc/config" "$R/data/usr/bin" "$R/CONTROL"
cp "$SRC/etc/init.d/meshlet-server" "$R/data/etc/init.d/"
cp "$SRC/etc/init.d/meshlet-agent" "$R/data/etc/init.d/"
cp "$SRC/etc/config/meshlet" "$R/data/etc/config/"
cp "$BINDIR/meshlet-server" "$BINDIR/meshlet-agent" "$BINDIR/meshlet-cli" "$R/data/usr/bin/"
chmod 755 "$R/data/etc/init.d/meshlet-server" "$R/data/etc/init.d/meshlet-agent" \
	"$R/data/usr/bin/meshlet-server" "$R/data/usr/bin/meshlet-agent" "$R/data/usr/bin/meshlet-cli"

cat > "$R/CONTROL/conffiles" <<'EOF'
/etc/config/meshlet
/etc/init.d/meshlet-server
/etc/init.d/meshlet-agent
EOF
cp "$SRC/CONTROL/postinst" "$R/CONTROL/postinst"
cp "$SRC/CONTROL/prerm" "$R/CONTROL/prerm"
SIZE=$(du -sk "$R/data" | cut -f1)
cat > "$R/CONTROL/control" <<EOF
Package: meshlet
Version: $REL
Depends: libc
Source: https://github.com/cuihairu/meshlet
SourceName: meshlet
License: Apache-2.0
Section: net
SourceDateEpoch: 1794931200
Maintainer: cuihairu <chuihairu@gmail.com>
Architecture: $ARCH
Installed-Size: $SIZE
Description: Self-organizing overlay mesh: hub server + device agent over WireGuard, with procd services. Dataplane optionally needs kmod-wireguard and the wg tool for key generation.
 自组织 overlay 组网：hub（server）+ 设备接入（agent），WireGuard 数据面，procd 服务。数据面可选依赖 kmod-wireguard 与 wg 工具（首启生成密钥）。
EOF

chmod 755 "$R"/CONTROL/postinst "$R"/CONTROL/prerm
mkdir -p "$OUT"
tar -czf "$R/control.tar.gz" -C "$R/CONTROL" ./control ./postinst ./prerm ./conffiles
tar -czf "$R/data.tar.gz" -C "$R/data" \
	etc/config/meshlet etc/init.d/meshlet-server etc/init.d/meshlet-agent \
	usr/bin/meshlet-server usr/bin/meshlet-agent usr/bin/meshlet-cli
echo "2.0" > "$R/debian-binary"
tar -czf "$OUT/meshlet_${REL}_${ARCH}.ipk" -C "$R" \
	./debian-binary ./control.tar.gz ./data.tar.gz
echo "built: $OUT/meshlet_${REL}_${ARCH}.ipk"

# ---- luci-app-meshlet (all) -------------------------------------------------
R="$STAGE/luci"
mkdir -p "$R/data/usr/lib/lua/luci/controller" "$R/data/usr/lib/lua/luci/model/cbi" \
	"$R/data/usr/lib/lua/luci/view/meshlet" "$R/CONTROL"
cp "$SRC/usr/lib/lua/luci/controller/meshlet.lua" "$R/data/usr/lib/lua/luci/controller/"
cp "$SRC/usr/lib/lua/luci/model/cbi/meshlet.lua" "$R/data/usr/lib/lua/luci/model/cbi/"
cp "$SRC/usr/lib/lua/luci/view/meshlet/status.htm" "$R/data/usr/lib/lua/luci/view/meshlet/"

cat > "$R/CONTROL/postinst" <<'EOF'
#!/bin/sh
# Drop the LuCI menu/index caches so the new controller routes are picked
# up without a reboot (idempotent; nothing to do when the cache is absent).
rm -f /tmp/luci-indexcache* 2>/dev/null || true
exit 0
EOF
cat > "$R/CONTROL/prerm" <<'EOF'
#!/bin/sh
exit 0
EOF
SIZE=$(du -sk "$R/data" | cut -f1)
cat > "$R/CONTROL/control" <<EOF
Package: luci-app-meshlet
Version: $REL
Depends: meshlet, curl
Source: https://github.com/cuihairu/meshlet
SourceName: luci-app-meshlet
License: Apache-2.0
Section: net
SourceDateEpoch: 1794931200
Maintainer: cuihairu <chuihairu@gmail.com>
Architecture: all
Installed-Size: $SIZE
Description: LuCI interface for meshlet: per-role settings page (hub server / device agent) and a live status dashboard (service state, online devices, recent logs).
 meshlet 的 LuCI 界面：分角色设置页（hub / agent）与实时状态面板（服务状态、在线设备、最近日志）。
EOF

chmod 755 "$R"/CONTROL/postinst "$R"/CONTROL/prerm
tar -czf "$R/control.tar.gz" -C "$R/CONTROL" ./control ./postinst ./prerm
# Archive the whole usr tree so the data member set includes directory
# entries: opkg's unpacker does not create missing parent directories for
# file-only members (view/meshlet/ was missing on the acceptance router and
# status.htm failed to unpack with "wfopen: ... No such file or directory").
tar -czf "$R/data.tar.gz" -C "$R/data" usr
echo "2.0" > "$R/debian-binary"
tar -czf "$OUT/luci-app-meshlet_${REL}_all.ipk" -C "$R" \
	./debian-binary ./control.tar.gz ./data.tar.gz
echo "built: $OUT/luci-app-meshlet_${REL}_all.ipk"

# ---- app-meta-meshlet (all) — the iStore-facing metadata package -----------
R="$STAGE/meta"
mkdir -p "$R/data/usr/lib/opkg/meta" "$R/data/www/luci-static/resources/app-icons" \
	"$R/CONTROL"
# The manifest version tracks the workspace version at build time.
sed "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" \
	"$SRC/app-meta/meshlet.json" > "$R/data/usr/lib/opkg/meta/meshlet.json"
cp "$REPO_DIR/assets/icons/meshlet.png" "$R/data/www/luci-static/resources/app-icons/meshlet.png"

cat > "$R/CONTROL/postinst" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$R/CONTROL/prerm" <<'EOF'
#!/bin/sh
exit 0
EOF
SIZE=$(du -sk "$R/data" | cut -f1)
cat > "$R/CONTROL/control" <<EOF
Package: app-meta-meshlet
Version: $REL
Depends: luci-app-meshlet
Source: https://github.com/cuihairu/meshlet
SourceName: app-meta-meshlet
License: Apache-2.0
Section: net
SourceDateEpoch: 1794931200
Maintainer: cuihairu <chuihairu@gmail.com>
Architecture: all
Installed-Size: $SIZE
Description: iStore app metadata for meshlet (icon and app manifest).
 meshlet 的 iStore 应用元数据（图标与应用清单）。
EOF

chmod 755 "$R"/CONTROL/postinst "$R"/CONTROL/prerm
tar -czf "$R/control.tar.gz" -C "$R/CONTROL" ./control ./postinst ./prerm
# Whole-tree archive with directory entries (see the luci-app note above).
tar -czf "$R/data.tar.gz" -C "$R/data" usr www
echo "2.0" > "$R/debian-binary"
tar -czf "$OUT/app-meta-meshlet_${REL}_all.ipk" -C "$R" \
	./debian-binary ./control.tar.gz ./data.tar.gz
echo "built: $OUT/app-meta-meshlet_${REL}_all.ipk"
echo "2.0" > "$R/debian-binary"
tar -czf "$OUT/app-meta-meshlet_${REL}_all.ipk" -C "$R" \
	./debian-binary ./control.tar.gz ./data.tar.gz
echo "built: $OUT/app-meta-meshlet_${REL}_all.ipk"
