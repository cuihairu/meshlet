#!/usr/bin/env python3
"""Verify the shipped hub unit under an unprivileged UID in an isolated netns.

Usage: sudo python3 scripts/verify-systemd.py SERVER_BINARY
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

ELF_MAGIC = b"\x7fELF"


class ExecLoopError(RuntimeError):
    """The unit keeps dying with 203/EXEC before it ever listens.

    Unlike a slow start this has a dedicated forensics dump and one full
    rebuild-and-retry (fresh unit name, copy/chown/chmod redone), because on
    hosted runners the signature appeared as an environment flake: three
    nightlies over three days failed identically with code-identical trees
    (43694301073 / 44003173881 / 44217087479), pointing at mount/executor
    drift on the runner fleet rather than at any commit.
    """


def run(args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} failed: {result.stderr.strip()}")
    return result


def unit_properties(unit):
    result = run(
        ["systemctl", "show", unit,
         "--property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,NRestarts"],
        check=False,
    )
    props = {}
    for line in result.stdout.splitlines():
        key, _, value = line.partition("=")
        props[key] = value
    return props


def diagnose(unit, namespace):
    """Failure-path forensics: hub journal, unit state, netns links.

    The readiness window only proves "the hub never listened"; without the
    journal we cannot tell a slow start from a crash loop (Restart=on-failure
    masks the latter). Dumped on stdout so `tee dataplane-systemd.log` in CI
    carries it into the evidence artifact.
    """
    probes = (
        ["journalctl", "--no-pager", f"--unit={unit}", "-n", "80", "--output=short-iso"],
        ["systemctl", "show", unit,
         "--property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,NRestarts"],
        ["ip", "netns", "exec", namespace, "ip", "-br", "addr"],
    )
    for args in probes:
        print(f"--- diagnose: {' '.join(args)}", flush=True)
        result = run(args, check=False)
        print(result.stdout.strip() or "(no output)", flush=True)
        if result.stderr.strip():
            print(result.stderr.strip(), flush=True)


def exec_forensics(unit, binary, namespace):
    """Forensics for a 203/EXEC crash loop: capture WHY the exec failed.

    203 means execve never succeeded — the interesting line ("Failed at step
    EXEC spawning ...: <errno>") is logged only on the FIRST failure, which a
    short `journalctl -n` tail loses to the 2s restart loop. Widen the
    window, then surface the errno line, the binary on-disk state, and the
    mount flags of everything the exec path crosses (/run tmpfs mounted
    noexec on a runner variant is the prime suspect for the recurring flake).
    """
    errno_filter = (
        "bash", "-lc",
        f"journalctl --no-pager --unit={unit} -n 200 --output=short-iso | "
        "grep -E 'Failed at step EXEC|Failed to locate executable|Permission denied|No such file or directory' | tail -5",
    )
    probes = (
        errno_filter,
        ["journalctl", "--no-pager", f"--unit={unit}", "-n", "200", "--output=short-iso"],
        ["systemctl", "show", unit,
         "--property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,NRestarts,ExecStart"],
        ["ls", "-la", str(binary.parent)],
        ["file", str(binary)],
        ["findmnt", "-T", str(binary)],
        ["findmnt", "/run"],
        ["ip", "netns", "exec", namespace, "ip", "-br", "addr"],
    )
    for args in probes:
        print(f"--- exec forensics: {' '.join(args)}", flush=True)
        result = run(args, check=False)
        print(result.stdout.strip() or "(no output)", flush=True)
        if result.stderr.strip():
            print(result.stderr.strip(), flush=True)


def attempt(binary, identity, group, repo, suffix):
    """Provision, start and verify one transient unit instance.

    Everything suffix-scoped (unit, netns, /run config dir, /var/lib state
    dir) is cleaned up in the finally block, so a caller may retry with a
    fresh suffix after an ExecLoopError.
    """
    unit = f"meshlet-verify-{suffix}"
    namespace = f"mlv{suffix}"
    config_dir = Path("/run") / unit
    service = Path("/run/systemd/system") / f"{unit}.service"
    state = Path("/var/lib") / unit
    # The exec'd binary lives on /usr/local — the shipped production exec
    # domain (/usr/local/bin) — NOT on /run and NOT inside the StateDirectory.
    # Two exec-hostile placement traps, both confirmed:
    #   - hosted runner fleets mount /run noexec on some image versions (run
    #     44228831360: X_OK false as root with mode 0o100755); that was the
    #     recurring 203/EXEC flake. ProtectSystem=strict keeps /usr read-only
    #     inside the unit, which does not affect exec.
    #   - with ProtectSystem=strict + ReadWritePaths + StateDirectory stacked
    #     on the same dir, systemd 259 refuses to exec any file under that
    #     bind (EACCES even for /bin/true; each directive alone execs fine).
    install_dir = Path("/usr/local") / unit
    installed = install_dir / "meshlet-server"
    try:
        config_dir.mkdir(mode=0o755)
        install_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary, installed)
        os.chmod(installed, 0o755)
        # Fail fast on a truncated or corrupted copy, or an exec-hostile
        # mount, instead of discovering it as an opaque 203/EXEC loop.
        with installed.open("rb") as fh:
            magic = fh.read(len(ELF_MAGIC))
        if magic != ELF_MAGIC:
            raise RuntimeError(f"copied binary lost ELF magic ({magic!r}); copy is truncated or corrupt")
        if not os.access(installed, os.X_OK):
            flags = os.statvfs(install_dir).f_flag
            print(
                f"--- exec pre-check: X_OK denied on {install_dir} "
                f"(mode={oct(installed.stat().st_mode)}, statvfs flags={flags:#x}, "
                f"ST_NOEXEC={'set' if flags & os.ST_NOEXEC else 'clear'})",
                flush=True,
            )
            for args in (["findmnt", "-T", str(install_dir)], ["findmnt", "/usr/local"], ["findmnt", "/run"]):
                print(f"--- exec pre-check: {' '.join(args)}", flush=True)
                result = run(args, check=False)
                print(result.stdout.strip() or "(no output)", flush=True)
            raise RuntimeError(f"copied binary is not executable: {oct(installed.stat().st_mode)}")
        key = config_dir / "hub.key"
        key.write_text(run(["wg", "genkey"]).stdout)
        os.chown(key, identity.pw_uid, identity.pw_gid)
        os.chmod(key, 0o600)
        config = config_dir / "server.toml"
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
        base = base.replace("ExecStart=/usr/local/bin/meshlet-server /etc/meshlet/meshlet.toml", f"ExecStart={installed} {config}")
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

        # Readiness window: generous bound for slow/cold hosted runners. A
        # crash loop exhausts it either way; a 203/EXEC loop is detected and
        # reported as soon as it is unambiguous (3+ restarts) instead of
        # burning the whole window on connection refusals.
        deadline = time.monotonic() + 60
        last_exec_check = 0.0
        while True:
            try:
                api("/api/v1/system/status")
                break
            except RuntimeError:
                now = time.monotonic()
                if now - last_exec_check > 3:
                    last_exec_check = now
                    props = unit_properties(unit)
                    restarts = int(props.get("NRestarts") or 0)
                    if props.get("ExecMainStatus") == "203" and restarts >= 3:
                        exec_forensics(unit, installed, namespace)
                        raise ExecLoopError(
                            f"unit {unit} is in a 203/EXEC crash loop "
                            f"(restarts={restarts}); exec never succeeded"
                        )
                if time.monotonic() > deadline:
                    diagnose(unit, namespace)
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
        shutil.rmtree(install_dir, ignore_errors=True)
        shutil.rmtree(config_dir, ignore_errors=True)
        shutil.rmtree(state, ignore_errors=True)


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise SystemExit("Usage: sudo python3 scripts/verify-systemd.py SERVER_BINARY")
    repo = Path(__file__).resolve().parent.parent
    binary = Path(sys.argv[1]).resolve(strict=True)
    identity = pwd.getpwnam("nobody")
    group = grp.getgrgid(identity.pw_gid).gr_name
    try:
        attempt(binary, identity, group, repo, uuid.uuid4().hex[:10])
    except ExecLoopError:
        # One full rebuild-and-retry with a fresh unit: copy/chown/chmod and
        # service registration redone from scratch. Transient provisioning
        # faults (partial copy, executor hiccup) clear here; a mount-level
        # cause fails again and keeps its forensics as the failure evidence.
        print("retrying once with a fresh unit after 203/EXEC crash loop", flush=True)
        attempt(binary, identity, group, repo, uuid.uuid4().hex[:10])


if __name__ == "__main__":
    main()
