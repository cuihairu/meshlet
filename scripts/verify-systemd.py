#!/usr/bin/env python3
"""Verify the shipped hub unit under an unprivileged UID in an isolated netns.

Usage: sudo python3 scripts/verify-systemd.py target/debug/meshlet-server
Creates no permanent accounts and removes its transient unit, netns and files.
"""
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time
import uuid


def run(args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} failed: {result.stderr.strip()}")
    return result


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise SystemExit("Usage: sudo python3 scripts/verify-systemd.py SERVER_BINARY")
    repo = Path(__file__).resolve().parent.parent
    binary = Path(sys.argv[1]).resolve(strict=True)
    identity = pwd.getpwnam("nobody")
    group = grp.getgrgid(identity.pw_gid).gr_name
    suffix = uuid.uuid4().hex[:10]
    unit = f"meshlet-verify-{suffix}"
    namespace = f"mlv{suffix}"
    root = Path("/run") / unit
    service = Path("/run/systemd/system") / f"{unit}.service"
    state = Path("/var/lib") / unit
    try:
        root.mkdir(mode=0o755)
        shutil.copy2(binary, root / "meshlet-server")
        os.chmod(root / "meshlet-server", 0o755)
        key = root / "hub.key"
        key.write_text(run(["wg", "genkey"]).stdout)
        os.chown(key, identity.pw_uid, identity.pw_gid)
        os.chmod(key, 0o600)
        config = root / "server.toml"
        config.write_text(
            f'bind = "127.0.0.1:18080"\ndatabase_path = "{state}/state.db"\n'
            f'[dataplane]\nenabled = true\ninterface = "wg0"\nlisten_port = 51820\nprivate_key_file = "{key}"\n'
        )
        os.chown(config, identity.pw_uid, identity.pw_gid)
        os.chmod(config, 0o600)
        run(["ip", "netns", "add", namespace])
        run(["ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up"])
        base = (repo / "deploy/systemd/meshlet-server.service").read_text()
        base = base.replace("User=meshlet", f"User={identity.pw_name}").replace("Group=meshlet", f"Group={group}")
        base = base.replace("/var/lib/meshlet", str(state)).replace("StateDirectory=meshlet", f"StateDirectory={unit}")
        base = base.replace("ExecStart=/usr/local/bin/meshlet-server /etc/meshlet/meshlet.toml", f"ExecStart={root}/meshlet-server {config}")
        base += "\n" + (repo / "deploy/systemd/meshlet-server.service.d/dataplane.conf").read_text()
        base += f"\n[Service]\nNetworkNamespacePath=/run/netns/{namespace}\n"
        service.write_text(base)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "start", unit])

        def api(path, body=None, cookie=None):
            args = ["ip", "netns", "exec", namespace, "curl", "--silent", "--show-error", "--fail", "--max-time", "3", "--include", "-H", "content-type: application/json"]
            if cookie:
                args += ["-H", f"cookie: {cookie}", "-H", "x-requested-with: XMLHttpRequest"]
            if body is not None:
                args += ["--data", json.dumps(body)]
            response = run(args + [f"http://127.0.0.1:18080{path}"]).stdout
            headers, _, data = response.partition("\n\n")
            return headers, json.loads(data) if data.strip() else None

        deadline = time.monotonic() + 15
        while True:
            try:
                api("/api/v1/system/status")
                break
            except RuntimeError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.2)
        headers, _ = api("/api/v1/auth/bootstrap", {"email": "unit@test.local", "password": "systemd-permissions-test"})
        cookie = next(line.split(":", 1)[1].strip().split(";", 1)[0] for line in headers.splitlines() if line.lower().startswith("set-cookie:"))
        _, network = api("/api/v1/networks", {"name": "unit-test", "overlay_cidr": "10.249.0.0/24"}, cookie)
        _, applied = api(f'/api/v1/networks/{network["id"]}/config-revisions/1/apply', {}, cookie)
        if applied["apply_status"] != "applied":
            raise RuntimeError(f"hub apply failed: {applied.get('error_summary')}")
        port = run(["ip", "netns", "exec", namespace, "wg", "show", "wg0", "listen-port"]).stdout.strip()
        if port != "51820":
            raise RuntimeError("WireGuard listen port does not match the applied plan")
        print("PASS: shipped unit + dataplane drop-in, unprivileged UID, 0600 key, WireGuard, forwarding/firewall, persisted apply/readback")
    finally:
        run(["systemctl", "stop", unit], check=False)
        run(["systemctl", "reset-failed", unit], check=False)
        service.unlink(missing_ok=True)
        run(["systemctl", "daemon-reload"], check=False)
        run(["ip", "netns", "del", namespace], check=False)
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(state, ignore_errors=True)


if __name__ == "__main__":
    main()
