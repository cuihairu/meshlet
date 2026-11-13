#!/usr/bin/env bash
# Package the OpenWrt .ipk set for the nightly release. Run after the musl
# release binaries exist (same contract as package-release.sh). Produces:
#   dist/meshlet-nightly-openwrt-<arch>.ipk        server+agent+cli+inits+UCI
#   dist/meshlet-nightly-openwrt-luci-app.ipk      LuCI app (arch all)
#   dist/meshlet-nightly-openwrt-app-meta.ipk      iStore metadata (arch all)
# Rolling asset names (no version in the filename), mirroring the Windows
# nightly assets; the version inside each package tracks Cargo.toml.
set -euo pipefail
[[ $# == 2 ]] || { printf 'Usage: %s TARGET ARCH\n' "$0" >&2; exit 2; }
target=$1
arch=$2
[[ $arch == x86_64 || $arch == aarch64 ]] || exit 2

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[[ -n $version ]] || { echo 'cannot read version from Cargo.toml' >&2; exit 1; }

mkdir -p dist
packaging/openwrt/build-ipk.sh "target/$target/release" dist --arch "$arch"
mv "dist/meshlet_${version}-1_${arch}.ipk" "dist/meshlet-nightly-openwrt-${arch}.ipk"
mv "dist/luci-app-meshlet_${version}-1_all.ipk" "dist/meshlet-nightly-openwrt-luci-app.ipk"
mv "dist/app-meta-meshlet_${version}-1_all.ipk" "dist/meshlet-nightly-openwrt-app-meta.ipk"
printf 'packaged openwrt ipks for %s:\n' "$arch"
ls -l dist/meshlet-nightly-openwrt-*.ipk
