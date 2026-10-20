#!/usr/bin/env bash
set -euo pipefail
# R-01 依赖边界门：planner 必须零第三方依赖（评审：不落库/不执行/不持密钥）
toml="$(dirname "$0")/../crates/meshlet-planner/Cargo.toml"
deps=$(sed -n "/^\[dependencies\]/,/^\[/p" "$toml" | grep -v "^\[" | grep -c "[A-Za-z]" || true)
if [ "$deps" != "0" ]; then echo "planner 依赖边界被破坏：$deps 条依赖"; exit 1; fi
echo "planner 依赖边界门通过（0 依赖）"
