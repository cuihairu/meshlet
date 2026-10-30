#!/usr/bin/env bash
# Build component-split .deb and .rpm packages for the nightly release.
#
# Requires already-built release binaries (target/<triple>/release/) and the
# built web console (console/dist). Requires dpkg-deb and rpmbuild (the rpm
# package) to be installed.
#
# Components (one package each, per the Linux package matrix):
#   meshlet-server  control-plane hub: server binary, systemd unit, dataplane
#                   drop-in, the web console static site, example config.
#   meshlet-agent   device agent: agent binary, systemd unit, example config.
#   meshlet-cli     command-line client: cli binary only (standalone, so a
#                   server or agent install does not ship a binary it never
#                   runs; per-binary installability is the distro convention).
#
# The web console (console/dist) is an independent static site served directly
# by the server through ServeDir, so it ships inside the meshlet-server package
# (not a separate tarball).
#
# The version is a prerelease sort ("0.0.0~nightly" sorts below any real 0.0.0
# release) so a nightly package is never a version bump. The packaged systemd
# units are rendered from deploy/systemd with the install prefix rewritten to
# /usr (packages must not install under /usr/local).
set -euo pipefail

fail() { printf 'package-deb-rpm: %s\n' "$*" >&2; exit 1; }

target=${1:-}
debarch=${2:-}
rpmarch=${3:-}
[[ -n $target && -n $debarch && -n $rpmarch ]] || {
  printf 'Usage: package-deb-rpm.sh <target-triple> <deb-arch> <rpm-arch>\n' >&2
  exit 1
}
case $debarch in amd64|arm64) ;; *) fail "unsupported deb arch: $debarch" ;; esac
case $rpmarch in x86_64|aarch64) ;; *) fail "unsupported rpm arch: $rpmarch" ;; esac

# Package-manager version: sorts below any real 0.0.0 release (prerelease).
version=0.0.0~nightly
# Asset filename version. GitHub replaces `~` with `.` in release asset names,
# so the uploaded files must carry the dotted form for README URLs and the
# SHA256SUMS lookups to resolve. The internal Version field keeps the `~`.
asset_version=0.0.0.nightly
release=1
maintainer='cuihairu <chuihairu@gmail.com>'

root=$(cd "$(dirname "$0")/.." && pwd)
binroot="$root/target/$target/release"
console="$root/console/dist"
units="$root/deploy/systemd"
dist="$root/dist"
mkdir -p "$dist"

command -v dpkg-deb >/dev/null || fail 'dpkg-deb is required'
command -v rpmbuild >/dev/null || fail 'rpmbuild is required (install the rpm package)'

for bin in meshlet-server meshlet-agent meshlet-cli; do
  [[ -x $binroot/$bin ]] || fail "missing built binary: $binroot/$bin"
done
[[ -f $console/index.html ]] || fail 'missing console build: console/dist (build the console first)'
[[ -f $units/meshlet-server.service && -f $units/meshlet-agent.service ]] || fail 'missing systemd units under deploy/systemd'

# --- Render packaged units and example configs into a shared staging root ---
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
rootdir="$work/root"
mkdir -p "$rootdir"

# Units: rewrite the /usr/local install prefix to the package prefix /usr.
render_unit() { # render_unit <name>
  sed -e 's#/usr/local/bin/#/usr/bin/#g' -e 's#/usr/local/share/meshlet#/usr/share/meshlet#g' \
    "$units/$1.service"
}
mkdir -p "$rootdir/usr/lib/systemd/system/meshlet-server.service.d"
render_unit meshlet-server > "$rootdir/usr/lib/systemd/system/meshlet-server.service"
render_unit meshlet-agent > "$rootdir/usr/lib/systemd/system/meshlet-agent.service"
cp "$units/meshlet-server.service.d/dataplane.conf" \
  "$rootdir/usr/lib/systemd/system/meshlet-server.service.d/dataplane.conf"

# Example configs: shipped beside /etc/meshlet as documentation, never as live
# config (live config is machine-specific and contains keys and tokens).
mkdir -p "$rootdir/etc/meshlet"
cat > "$rootdir/etc/meshlet/meshlet.toml.example" <<'CONFIG'
# Meshlet control plane example configuration (from the meshlet-server package).
# Copy to /etc/meshlet/meshlet.toml, generate a hub key, then start the
# service: systemctl enable --now meshlet-server
bind = "127.0.0.1:8080"
database_path = "/var/lib/meshlet/meshlet.db"
console_dir = "/usr/share/meshlet/console"
# Set true when serving through an HTTPS reverse proxy.
cookie_secure = false
[dataplane]
enabled = true
interface = "wg0"
listen_port = 51820
private_key_file = "/etc/meshlet/hub.key"
[backup]
dir = "/var/lib/meshlet/backups"
auto = false
CONFIG
cat > "$rootdir/etc/meshlet/agent.toml.example" <<'CONFIG'
# Meshlet device agent example configuration (from the meshlet-agent package).
# Fill in server_url and the bootstrap fields, then copy to
# /etc/meshlet/agent.toml and start: systemctl enable --now meshlet-agent
server_url = "https://hub.example.com"
state_dir = "/var/lib/meshlet-agent"
bootstrap_token = "replace-me"
device_name = "replace-me"
[dataplane]
enabled = true
interface = "wg0"
private_key_file = "/etc/meshlet/agent.key"
poll_interval_secs = 30
hub_endpoint = "hub.example.com:51820"
CONFIG

mkdir -p "$rootdir/usr/bin" "$rootdir/usr/share/meshlet"
cp "$binroot/meshlet-server" "$binroot/meshlet-agent" "$binroot/meshlet-cli" "$rootdir/usr/bin/"
cp -R "$console" "$rootdir/usr/share/meshlet/console"

# Normalize modes regardless of the invoking umask: executables 0755, all other
# files 0644, directories 0755 — the modes a distro package must carry.
chmod 0755 "$rootdir"/usr/bin/meshlet-server "$rootdir"/usr/bin/meshlet-agent "$rootdir"/usr/bin/meshlet-cli
find "$rootdir" -type d -exec chmod 0755 {} +
find "$rootdir" -type f ! -path "$rootdir/usr/bin/*" -exec chmod 0644 {} +

# --- Shared maintenance scriptlets (POSIX sh, idempotent) ---
# postinst/%post: create the service group and account, the state directory
# and /etc/meshlet, then reload units. Live config is deliberately NOT
# generated: it is machine-specific, so the service stays disabled until an
# operator copies the shipped example config.
scriptlet_create_user() { # scriptlet_create_user <name> <state-dir>
  local name=$1 state=$2
  cat <<SH
#!/bin/sh
set -e
if ! getent group "$name" >/dev/null 2>&1; then
  groupadd --system "$name"
fi
if ! id -u "$name" >/dev/null 2>&1; then
  useradd --system --gid "$name" --home-dir "$state" \
    --shell "\$(command -v nologin || echo /usr/sbin/nologin)" "$name"
fi
mkdir -p "$state" /etc/meshlet
chown "$name:$name" "$state"
chmod 0700 "$state"
chmod 0755 /etc/meshlet
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
SH
}
scriptlet_daemon_reload() {
  cat <<'SH'
#!/bin/sh
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
SH
}

# Files under a package's staging prefix, one per line (for rpm %files).
package_files() { # package_files <paths...>
  local path
  for path in "$@"; do
    if [[ $path == */ ]]; then
      (cd "$rootdir" && find "$path" -type f | sort)
    else
      printf '%s\n' "$path"
    fi
  done
}

# --- Build one .deb via dpkg-deb ---
build_deb() { # build_deb <pkg> <desc> <postinst-or-empty> <files...>
  local pkg=$1 desc=$2 postinst=$3
  shift 3
  local pkgdir="$work/deb-$pkg" path
  mkdir -p "$pkgdir/DEBIAN"
  for path in "$@"; do
    mkdir -p "$pkgdir/$(dirname "$path")"
    cp -a "$rootdir/$path" "$pkgdir/$path"
  done
  {
    printf 'Package: %s\n' "$pkg"
    printf 'Version: %s\n' "$version"
    printf 'Section: net\nPriority: optional\nArchitecture: %s\n' "$debarch"
    printf 'Maintainer: %s\n' "$maintainer"
    printf 'Description: %s\n' "$desc"
  } > "$pkgdir/DEBIAN/control"
  if [[ -n $postinst ]]; then
    cp "$postinst" "$pkgdir/DEBIAN/postinst"
    chmod 0755 "$pkgdir/DEBIAN/postinst"
  fi
  # --root-owner-group forces root:root tar ownership even when built as a
  # non-root user (CI runners are non-root).
  dpkg-deb --build --root-owner-group "$pkgdir" "$dist/${pkg}_${asset_version}_${debarch}.deb" >/dev/null
}

# --- Build one .rpm via rpmbuild ---
build_rpm() { # build_rpm <pkg> <summary> <post-or-empty> <files...>
  local pkg=$1 summary=$2 post=$3
  shift 3
  local topdir="$work/rpm-$pkg" spec="$work/rpm-$pkg/SPECS/$pkg.spec"
  local path
  mkdir -p "$topdir"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS}
  {
    printf 'Name: %s\n' "$pkg"
    printf 'Version: %s\n' "$version"
    printf 'Release: %s\n' "$release"
    printf 'Summary: %s\n' "$summary"
    printf 'License: Apache-2.0\n'
    printf 'BuildArch: %s\n' "$rpmarch"
    printf '%%description\n%s\n' "$summary"
    printf '%%install\n'
    while IFS= read -r path; do
      printf 'mkdir -p "%%{buildroot}/%s"\n' "$(dirname "$path")"
      printf 'cp -a "%%{_pkgroot}/%s" "%%{buildroot}/%s"\n' "$path" "$path"
    done < <(package_files "$@")
    printf '%%files\n'
    while IFS= read -r path; do
      printf '%%attr(-,root,root) /%s\n' "$path"
    done < <(package_files "$@")
    if [[ -n $post ]]; then
      printf '%%post\n'
      cat "$post"
    fi
    printf '%%postun\nif command -v systemctl >/dev/null 2>&1; then\n  systemctl daemon-reload >/dev/null 2>&1 || true\nfi\nexit 0\n'
  } > "$spec"
  # %install copies each staged file from _pkgroot into whatever buildroot the
  # local rpm configuration chose, so nothing depends on buildroot conventions.
  rpmbuild --define "_topdir $topdir" --define "_pkgroot $rootdir" \
    --define 'debug_package %{nil}' \
    --define '_build_id_links none' --define '_missing_build_ids_terminate_build 0' \
    -bb "$spec" >/dev/null
  mv "$topdir"/RPMS/"$rpmarch"/*.rpm "$dist/${pkg}-${asset_version}-${release}.${rpmarch}.rpm"
}

user_server="$work/user-server.sh"
user_agent="$work/user-agent.sh"
reload_script="$work/reload.sh"
scriptlet_create_user meshlet /var/lib/meshlet > "$user_server"
scriptlet_create_user meshlet-agent /var/lib/meshlet-agent > "$user_agent"
scriptlet_daemon_reload > "$reload_script"

server_paths=(
  usr/bin/meshlet-server
  usr/lib/systemd/system/meshlet-server.service
  usr/lib/systemd/system/meshlet-server.service.d/dataplane.conf
  etc/meshlet/meshlet.toml.example
  'usr/share/meshlet/console/'
)
agent_paths=(
  usr/bin/meshlet-agent
  usr/lib/systemd/system/meshlet-agent.service
  etc/meshlet/agent.toml.example
)
cli_paths=(usr/bin/meshlet-cli)

build_deb meshlet-server 'Meshlet control plane server (hub) with web console' "$user_server" "${server_paths[@]}"
build_deb meshlet-agent 'Meshlet device agent with systemd unit' "$user_agent" "${agent_paths[@]}"
build_deb meshlet-cli 'Meshlet command-line client' '' "${cli_paths[@]}"

build_rpm meshlet-server 'Meshlet control plane server (hub) with web console' "$user_server" "${server_paths[@]}"
build_rpm meshlet-agent 'Meshlet device agent with systemd unit' "$user_agent" "${agent_paths[@]}"
build_rpm meshlet-cli 'Meshlet command-line client' '' "${cli_paths[@]}"

printf 'Built %s packages (%s/%s):\n' "$version" "$debarch" "$rpmarch"
ls -1 "$dist"/*_"${debarch}".deb "$dist"/*."${rpmarch}".rpm
