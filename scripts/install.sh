#!/usr/bin/env bash
# Install an official Meshlet release. Existing configuration, credentials and data survive upgrades.
set -euo pipefail
umask 077

usage() {
  cat <<'HELP'
Usage: install.sh server|agent [options]
  --version TAG          Release tag (default: nightly)
  --server-url URL       Agent control plane URL (required for a new agent)
  --hub-endpoint HOST:PORT  Agent WireGuard endpoint (required for a new agent)
  --bootstrap-token TOKEN   Agent self-registration token (required for a new agent)
  --name NAME            Agent device name (default: hostname)
  --bind ADDRESS         New server bind address (default: 127.0.0.1:8080)
  --no-start             Install/configure without starting the service
  --help                Show this help
Environment: MESHLET_REPO=owner/repo (default: cuihairu/meshlet)
Offline/staged installs: set MESHLET_INSTALL_ARCHIVE and MESHLET_INSTALL_SHA256SUMS.
Re-run the same role to upgrade; existing TOML files and private keys are preserved.
HELP
}
fail() { printf 'meshlet installer: %s\n' "$*" >&2; exit 1; }
quote_toml() {
  local value=$1
  [[ $value != *$'\n'* && $value != *$'\r'* ]] || fail 'configuration values must be a single line'
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  printf '"%s"' "$value"
}

role=${1:-}
if [[ $role == --help || $role == -h || -z $role ]]; then usage; exit 0; fi
[[ $role == server || $role == agent ]] || fail 'choose server or agent'
shift
version=nightly
repo=${MESHLET_REPO:-cuihairu/meshlet}
server_url=''
hub_endpoint=''
bootstrap_token=''
device_name=$(hostname)
bind=127.0.0.1:8080
start_service=true
while (($#)); do
  case $1 in
    --version|--server-url|--hub-endpoint|--bootstrap-token|--name|--bind)
      (($# >= 2)) || fail "missing value for $1"
      case $1 in
        --version) version=$2 ;; --server-url) server_url=$2 ;;
        --hub-endpoint) hub_endpoint=$2 ;; --bootstrap-token) bootstrap_token=$2 ;;
        --name) device_name=$2 ;; --bind) bind=$2 ;;
      esac
      shift 2 ;;
    --no-start) start_service=false; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done
[[ $version =~ ^[A-Za-z0-9._-]+$ ]] || fail 'invalid release tag'
[[ $repo =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail 'invalid repository name'
[[ $(uname -s) == Linux ]] || fail 'this installer requires Linux with systemd'
case $(uname -m) in
  x86_64|amd64) arch=x86_64 ;; aarch64|arm64) arch=aarch64 ;;
  *) fail 'supported CPU architectures: x86_64 and aarch64' ;;
esac
[[ $(id -u) == 0 ]] || fail 'run with sudo bash (see README)'
command -v systemctl >/dev/null || fail 'systemd is required'
[[ -d /run/systemd/system ]] || fail 'systemd must be running'
config=/etc/meshlet/meshlet.toml
[[ $role == agent ]] && config=/etc/meshlet/agent.toml
if [[ $role == agent && ! -f $config ]]; then
  [[ $server_url == https://* || $server_url == http://* ]] || fail '--server-url must use http:// or https://'
  [[ -n $hub_endpoint && -n $bootstrap_token && -n $device_name ]] || fail 'new agents require --hub-endpoint, --bootstrap-token and a device name'
fi
# Validate TOML values before installing packages or changing files.
for value in "$server_url" "$hub_endpoint" "$bootstrap_token" "$device_name" "$bind"; do quote_toml "$value" >/dev/null; done

if command -v apt-get >/dev/null; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl tar coreutils iproute2 wireguard-tools iptables iputils-ping
elif command -v dnf >/dev/null; then
  dnf install -y ca-certificates curl tar coreutils iproute wireguard-tools iptables iputils
else
  fail 'supported package managers: apt-get and dnf; use the manual installation guide for other distributions'
fi
for tool in curl sha256sum tar wg ip iptables sysctl useradd install; do command -v "$tool" >/dev/null || fail "required tool missing: $tool"; done
if [[ ! -f $config ]] && ip link show wg0 >/dev/null 2>&1; then
  fail 'wg0 already exists; use the manual installation guide to choose a dedicated interface before starting Meshlet'
fi
work_dir=$(mktemp -d /tmp/meshlet-install.XXXXXXXX)
trap 'rm -rf -- "$work_dir"' EXIT
asset="meshlet-linux-${arch}.tar.gz"
base="https://github.com/${repo}/releases/download/${version}"
archive=${MESHLET_INSTALL_ARCHIVE:-}
checksums=${MESHLET_INSTALL_SHA256SUMS:-}
if [[ -n $archive || -n $checksums ]]; then
  [[ -n $archive && -n $checksums ]] || fail 'staged installs require both archive and checksum variables'
  [[ -f $archive && -f $checksums ]] || fail 'staged archive or checksum file is missing'
  expected=$(awk -v file="$asset" '$2 == file && $1 ~ /^[0-9a-f]+$/ && length($1) == 64 {print $1}' "$checksums")
  [[ $(wc -l <<<"$expected") == 1 ]] || fail "missing or duplicate checksum for $asset"
  actual=$(sha256sum "$archive" | awk '{print $1}')
  [[ "$actual" == "$expected" ]] || fail "checksum failed for $archive"
  printf 'Verifying staged Meshlet %s (%s)…\n' "$version" "$arch"
  cp -- "$archive" "$work_dir/$asset"
else
  printf 'Downloading Meshlet %s (%s)…\n' "$version" "$arch"
  curl --fail --show-error --silent --location --retry 3 --proto '=https' --tlsv1.2 "$base/$asset" -o "$work_dir/$asset"
  curl --fail --show-error --silent --location --retry 3 --proto '=https' --tlsv1.2 "$base/SHA256SUMS" -o "$work_dir/SHA256SUMS"
  # Select exactly one checksum; never ask sha256sum to read arbitrary release filenames.
  awk -v file="$asset" '$2 == file && $1 ~ /^[0-9a-f]+$/ && length($1) == 64 {print}' "$work_dir/SHA256SUMS" > "$work_dir/selected.sha256"
  [[ $(wc -l < "$work_dir/selected.sha256") == 1 ]] || fail "missing or duplicate checksum for $asset"
  (cd "$work_dir" && sha256sum --check selected.sha256)
fi
mkdir "$work_dir/package"
tar -xzf "$work_dir/$asset" --no-same-owner -C "$work_dir/package"
package="$work_dir/package"
[[ -x $package/meshlet-server && -x $package/meshlet-agent && -f $package/systemd/meshlet-server.service && -f $package/systemd/meshlet-agent.service ]] || fail 'release archive is incomplete'
account=meshlet
[[ $role == agent ]] && account=meshlet-agent
state_dir="/var/lib/$account"
if ! id "$account" >/dev/null 2>&1; then
  useradd --system --user-group --home-dir "$state_dir" --shell /usr/sbin/nologin "$account"
fi
install -d -m 0755 /etc/meshlet /usr/local/bin /usr/local/share/meshlet
install -d -m 0700 -o "$account" -g "$account" "$state_dir"
# Stage executable beside its final location, then atomically replace it.
install -m 0755 "$package/meshlet-$role" "/usr/local/bin/.meshlet-$role.new"
mv -f "/usr/local/bin/.meshlet-$role.new" "/usr/local/bin/meshlet-$role"
if [[ -x $package/meshlet-cli ]]; then
  install -m 0755 "$package/meshlet-cli" /usr/local/bin/.meshlet-cli.new
  mv -f /usr/local/bin/.meshlet-cli.new /usr/local/bin/meshlet-cli
fi
key="/etc/meshlet/$role.key"
[[ $role == server ]] && key=/etc/meshlet/hub.key
if [[ ! -f $key ]]; then
  wg genkey > "$work_dir/private.key"
  install -m 0600 -o "$account" -g "$account" "$work_dir/private.key" "$key"
fi
if [[ ! -f $config ]]; then
  if [[ $role == server ]]; then
    [[ -f $package/console/index.html ]] || fail 'release does not contain the console'
    {
      printf 'bind = %s\n' "$(quote_toml "$bind")"
      cat <<'CONFIG'
database_path = "/var/lib/meshlet/meshlet.db"
console_dir = "/usr/local/share/meshlet/console"
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
    } > "$work_dir/config.toml"
  else
    {
      printf 'server_url = %s\n' "$(quote_toml "$server_url")"
      printf 'state_dir = %s\n' "$(quote_toml "$state_dir")"
      printf 'bootstrap_token = %s\n' "$(quote_toml "$bootstrap_token")"
      printf 'device_name = %s\n' "$(quote_toml "$device_name")"
      cat <<'CONFIG'
[dataplane]
enabled = true
interface = "wg0"
private_key_file = "/etc/meshlet/agent.key"
poll_interval_secs = 30
CONFIG
      printf 'hub_endpoint = %s\n' "$(quote_toml "$hub_endpoint")"
    } > "$work_dir/config.toml"
  fi
  install -m 0600 -o "$account" -g "$account" "$work_dir/config.toml" "$config"
else
  printf 'Preserving existing configuration: %s\n' "$config"
fi
if [[ $role == server ]]; then
  [[ -f $package/console/index.html ]] || fail 'release does not contain the console'
  install -d -m 0755 /usr/local/share/meshlet/console
  cp -R "$package/console/." /usr/local/share/meshlet/console/
  chmod -R a+rX /usr/local/share/meshlet/console
  install -d -m 0755 /etc/systemd/system/meshlet-server.service.d
  install -m 0644 "$package/systemd/meshlet-server.service.d/dataplane.conf" /etc/systemd/system/meshlet-server.service.d/dataplane.conf
fi
install -m 0644 "$package/systemd/meshlet-$role.service" "/etc/systemd/system/meshlet-$role.service"
install -m 0644 "$package/BUILD_INFO" "/usr/local/share/meshlet/$role-build-info"
if $start_service; then
  systemctl daemon-reload
fi
if $start_service; then
  systemctl enable "meshlet-$role.service"
  systemctl restart "meshlet-$role.service"
  systemctl is-active --quiet "meshlet-$role.service" || fail "service did not start; inspect journalctl -u meshlet-$role"
fi
printf 'Installed Meshlet %s (%s). Configuration: %s\n' "$version" "$role" "$config"
cat "$package/BUILD_INFO"
if [[ $role == server ]]; then
  printf '\nOpen the console at http://127.0.0.1:8080 (or your configured bind address).\n'
  printf 'For a remote VPS: ssh -L 8080:127.0.0.1:8080 user@your-vps\n'
  printf 'Create the administrator, network and bootstrap token; allow the network UDP port in the VPS firewall.\n'
else
  printf '\nApprove this device in the console, then apply the current network revision.\n'
fi
