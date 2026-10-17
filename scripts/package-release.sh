#!/usr/bin/env bash
# Run after building Rust release binaries and console/dist.
set -euo pipefail
[[ $# == 2 ]] || { printf 'Usage: %s TARGET ARCH\n' "$0" >&2; exit 2; }
target=$1
arch=$2
[[ $arch == x86_64 || $arch == aarch64 ]] || exit 2
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
for binary in meshlet-server meshlet-agent meshlet-cli; do
  install -m 0755 "target/$target/release/$binary" "$stage/$binary"
done
[[ -f console/dist/index.html ]]
cp -R console/dist "$stage/console"
cp -R deploy/systemd "$stage/systemd"
install -m 0755 scripts/install.sh "$stage/install.sh"
cp LICENSE "$stage/LICENSE"
source_dirty=false
[[ -z $(git status --porcelain) ]] || source_dirty=true
printf 'repository=%s\ncommit=%s\nbuilt_at=%s\ntarget=%s\nsource_dirty=%s\n' "${GITHUB_REPOSITORY:-cuihairu/meshlet}" "${GITHUB_SHA:-$(git rev-parse HEAD)}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$target" "$source_dirty" > "$stage/BUILD_INFO"
mkdir -p dist
tar -czf "dist/meshlet-linux-$arch.tar.gz" -C "$stage" .
