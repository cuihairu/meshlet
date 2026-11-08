use std::collections::BTreeSet;

use meshlet_agent::Reason;
use meshlet_network::linux::LinuxNetworkBackend;
use meshlet_network::nat::alias_nat_rules;

use crate::common::{
    agent_in, alias_mapping, count_prefix_lines, hub_plan, leaf_plan, netns_exec, require_ok, sudo,
    tag, temp_state_dir, wg_genkey, wg_pubkey, Topology, ALIAS_OWNER, HANDSHAKE_TIMEOUT,
};

#[test]
fn agent_applies_the_plan_and_replays_after_a_reboot() {
    let topo = match Topology::setup("r") {
        Some(t) => t,
        None => return, // 已打印 SKIP:
    };

    // ---- hub 侧先行（server 数据面，与 agent 无关） ------------------------
    let mut hub_backend = LinuxNetworkBackend::new()
        .with_netns(&topo.hub.netns)
        .with_sudo()
        .with_interface("wg0");
    hub_backend
        .apply_device_plan_sync(
            &hub_plan(&topo),
            Some(topo.hub.private_key.clone()),
            None,
            &BTreeSet::new(),
        )
        .expect("hub applies its own plan");
    // 内核级 MTU 断言（#51①）：计划里的 MTU 真的落在了接口上。
    assert_eq!(
        hub_backend.inspect_sync().expect("hub snapshot").tunnel_mtu,
        Some(1380),
        "hub tunnel MTU must match the plan in the kernel"
    );

    // ---- 1. agent 应用设备计划（隧道 + 他人网关的前缀路由） ----------------
    // 客户端计划的路由 = 他人网关发布的 LAN/Alias 前缀经该网关虚拟 IP，
    // AllowedIPs 恰好覆盖同一批前缀 + Overlay（与 server `build_device_plan`
    // 同构，§7.2）。二者必须一致：目的前缀不在 AllowedIPs 里时 WireGuard
    // 不发包（路由装了也不通），所以「AllowedIPs 与目标路由一致」是可测约束。
    let a_dir = temp_state_dir("state-a");
    let mut a_agent = agent_in(&topo.a, &a_dir);
    let a_plan = leaf_plan(
        &topo.a,
        &topo.hub,
        &["10.240.0.0/16", "192.168.1.0/24", "10.241.1.0/24"],
        &[
            ("10.241.1.0/24", &topo.gw.overlay),
            ("192.168.1.0/24", &topo.gw.overlay),
        ],
        Vec::new(),
        "hash-a1",
    );

    // 首装：无账本 → 必须应用（NoLocalLedger）。
    let decision = a_agent.reconcile(&a_plan).expect("agent applies plan");
    assert!(decision.needs_apply);
    assert_eq!(decision.reason, Reason::NoLocalLedger);
    assert!(a_agent.state_path().exists(), "ledger written after apply");

    // B 侧同样应用（另一个 agent 实例）。
    let b_dir = temp_state_dir("state-b");
    let mut b_agent = agent_in(&topo.b, &b_dir);
    let b_plan = leaf_plan(
        &topo.b,
        &topo.hub,
        &["10.240.0.0/16", "192.168.1.0/24", "10.241.1.0/24"],
        &[
            ("10.241.1.0/24", &topo.gw.overlay),
            ("192.168.1.0/24", &topo.gw.overlay),
        ],
        Vec::new(),
        "hash-b1",
    );
    b_agent.reconcile(&b_plan).expect("agent B applies plan");

    for (label, ns) in [("A", &topo.a.netns), ("B", &topo.b.netns)] {
        assert!(
            topo.wait_handshake(ns),
            "{label} handshake did not complete"
        );
    }
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "A -> B via hub"
    );
    assert!(
        topo.ping_within(&topo.b.netns, &topo.a.overlay, HANDSHAKE_TIMEOUT),
        "B -> A via hub"
    );

    // 无变更时不重放（§10.1 有变更才重放）。
    let decision = a_agent.reconcile(&a_plan).expect("second reconcile");
    assert!(!decision.needs_apply, "unchanged plan must not be replayed");
    assert_eq!(decision.reason, Reason::UpToDate);

    // ---- 2. 服务端新修订 → 重放 -------------------------------------------
    let a_plan_v2 = leaf_plan(
        &topo.a,
        &topo.hub,
        &[
            "10.240.0.0/16",
            "192.168.1.0/24",
            "192.168.2.0/24",
            "10.241.1.0/24",
        ],
        &[
            ("10.241.1.0/24", &topo.gw.overlay),
            ("192.168.1.0/24", &topo.gw.overlay),
            ("192.168.2.0/24", &topo.gw.overlay),
        ],
        Vec::new(),
        "hash-a2",
    );
    let decision = a_agent.reconcile(&a_plan_v2).expect("replay new revision");
    assert!(decision.needs_apply);
    assert_eq!(decision.reason, Reason::DesiredConfigChanged);
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "data path survives replay"
    );

    // ---- 3. 主机重启：账本说已应用，内核接口没了 → 判定漂移并重放（#32）----
    require_ok(
        &netns_exec(&topo.a.netns, &["ip", "link", "del", "wg0"]),
        "simulate host reboot losing the tunnel",
    );
    assert!(
        !topo.ping(&topo.a.netns, &topo.b.overlay),
        "tunnel is gone after the simulated reboot"
    );
    // 账本仍记着 hash-a2 —— 这正是「重启后账本记 applied」的现场。
    let decision = a_agent.reconcile(&a_plan_v2).expect("replay after reboot");
    assert!(decision.needs_apply, "lost tunnel must be replayed");
    assert_eq!(decision.reason, Reason::KernelDrift);
    assert!(
        topo.wait_handshake(&topo.a.netns),
        "A handshake after replay"
    );
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "A -> B recovered after replay"
    );

    // 重放后再次对账：无漂移 → 不重放。
    assert!(!a_agent.reconcile(&a_plan_v2).unwrap().needs_apply);

    // ---- 3.5 MTU：计划值落到内核；内核读数不符 → 判漂移并纠回（#51）-------
    let a_backend = LinuxNetworkBackend::new()
        .with_netns(&topo.a.netns)
        .with_sudo()
        .with_interface("wg0");
    let mut mtu_plan = a_plan_v2.clone();
    mtu_plan.tunnel.mtu = Some(1380);
    // MTU 是计划的一部分：服务端哈希覆盖整份计划，MTU 变化即新修订。
    mtu_plan.desired_config_hash = "hash-a3".into();
    let decision = a_agent.reconcile(&mtu_plan).expect("apply mtu plan");
    assert!(decision.needs_apply);
    assert_eq!(decision.reason, Reason::DesiredConfigChanged);
    assert_eq!(
        a_backend.inspect_sync().expect("A snapshot").tunnel_mtu,
        Some(1380),
        "planned MTU must land in the kernel"
    );

    // 内核读数被改走（手工改动 / 半途失败）→ 对账判漂移，重放纠回。
    require_ok(
        &netns_exec(&topo.a.netns, &["ip", "link", "set", "wg0", "mtu", "1420"]),
        "sabotage tunnel mtu",
    );
    let decision = a_agent
        .reconcile(&mtu_plan)
        .expect("reconcile after mtu sabotage");
    assert!(decision.needs_apply, "mtu mismatch must be replayed");
    assert_eq!(decision.reason, Reason::KernelDrift);
    assert_eq!(
        a_backend.inspect_sync().expect("A snapshot").tunnel_mtu,
        Some(1380),
        "replay restores the planned MTU"
    );

    // 设备侧实测证据（#51②）：内核读数 + 大包探测（`ping -M do`，载荷 =
    // 计划 MTU − 28）随心跳回传——探测目标 = hub overlay 地址，走真实隧道。
    let evidence = a_agent.collect_evidence(Some(&mtu_plan));
    assert_eq!(evidence.tunnel_mtu, Some(1380), "kernel reading reported");
    assert_eq!(
        evidence.mtu_probe_payload,
        Some(1352),
        "large-packet probe must pass at planned MTU - 28 via the tunnel"
    );

    // ---- 4. 网关侧：Alias NAT 随计划下发，映射删除即整单元清理（§12.6）----
    let gw_dir = temp_state_dir("state-gw");
    let mut gw_agent = agent_in(&topo.gw, &gw_dir);
    let gw_plan = leaf_plan(
        &topo.gw,
        &topo.hub,
        &["10.240.0.0/16"],
        &[],
        alias_nat_rules(&alias_mapping()),
        "hash-gw1",
    );
    gw_agent
        .reconcile(&gw_plan)
        .expect("gateway applies nat rules");
    assert!(topo.wait_handshake(&topo.gw.netns), "G handshake");
    // 网关证据（#57②）：心跳回传的 NAT 读数反映内核实际（有规则 → true）。
    let gw_evidence = gw_agent.collect_evidence(Some(&gw_plan));
    assert_eq!(
        gw_evidence.nat_rules_present,
        Some(true),
        "gateway must report its meshlet NAT rules as present"
    );
    // Direct 模式（非 Alias）路由：计划里的 `192.168.1.0/24 via 网关` 让远端
    // 真实 LAN 直接可达（§8.1 验收「发布 CIDR 后远端可访问」）。
    assert!(
        topo.ping_within(&topo.a.netns, "192.168.1.5", HANDSHAKE_TIMEOUT),
        "A -> remote LAN via the gateway (direct route from the plan)"
    );
    // Alias 路径：计划里的 Alias 前缀 + 网关侧 DNAT/SNAT 规则打通同一网段。
    assert!(
        topo.ping_within(&topo.a.netns, "10.241.1.5", HANDSHAKE_TIMEOUT),
        "A -> alias prefix reaches the real LAN behind G"
    );

    // 预埋一条非 Meshlet 规则（用户视角的外来规则）。
    require_ok(
        &netns_exec(
            &topo.gw.netns,
            &[
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-d",
                "203.0.113.0/24",
                "-j",
                "ACCEPT",
                "-m",
                "comment",
                "--comment",
                "user rule",
            ],
        ),
        "plant foreign nat rule",
    );

    // 映射被删除（新修订，NAT 规则清空）→ agent 按所有权注释精确清理。
    let gw_plan_v2 = leaf_plan(
        &topo.gw,
        &topo.hub,
        &["10.240.0.0/16"],
        &[],
        Vec::new(),
        "hash-gw2",
    );
    let decision = gw_agent.reconcile(&gw_plan_v2).expect("gateway drops nat");
    assert!(decision.needs_apply);
    assert_eq!(decision.reason, Reason::DesiredConfigChanged);
    let prerouting = topo.nat_rules(&topo.gw.netns, "PREROUTING");
    assert!(
        !prerouting.contains(ALIAS_OWNER),
        "meshlet alias rules must be gone:\n{prerouting}"
    );
    assert!(
        prerouting.contains("user rule"),
        "foreign rule must survive:\n{prerouting}"
    );
    assert!(
        !topo.ping(&topo.a.netns, "10.241.1.5"),
        "alias path must fail after the mapping is deleted"
    );
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "overlay must stay unaffected by the mapping removal"
    );
    // 清理后的证据如实翻转（#57②）：内核实际没有 Meshlet NAT 规则 → false。
    let gw_evidence = gw_agent.collect_evidence(Some(&gw_plan_v2));
    assert_eq!(
        gw_evidence.nat_rules_present,
        Some(false),
        "evidence must report the kernel after the ownership cleanup"
    );

    // ---- 4.5 身份级漂移端到端（M2）：Reason 归因 + 非 meshlet 资源永不动 ----
    // (a) 隧道上多出一个外来 peer（身份不在计划里）→ KernelDrift 并清掉。
    let stranger_private = wg_genkey().expect("generate a stranger key");
    let stranger_public = wg_pubkey(&stranger_private).expect("derive the stranger key");
    require_ok(
        &netns_exec(
            &topo.a.netns,
            &[
                "wg",
                "set",
                "wg0",
                "peer",
                &stranger_public,
                "allowed-ips",
                "10.244.0.0/24",
            ],
        ),
        "plant a foreign peer on A's tunnel",
    );
    let decision = a_agent
        .reconcile(&mtu_plan)
        .expect("reconcile after peer injection");
    assert!(decision.needs_apply, "an extra peer is kernel drift");
    assert_eq!(decision.reason, Reason::KernelDrift);
    let peers = a_backend
        .inspect_sync()
        .expect("A snapshot after repair")
        .peers;
    assert!(
        !peers.iter().any(|p| p.public_key == stranger_public),
        "the foreign peer must be removed: {peers:?}"
    );
    assert_eq!(
        peers
            .iter()
            .map(|p| p.public_key.clone())
            .collect::<Vec<_>>(),
        vec![topo.hub.public_key.clone()],
        "A's planned peer must survive the repair"
    );
    assert!(
        topo.ping_within(&topo.a.netns, &topo.b.overlay, HANDSHAKE_TIMEOUT),
        "data path must survive the peer repair"
    );

    // (b) 隧道接口上一条未打 Meshlet 标记的路由 → 不算漂移（UpToDate），
    // 且该路由原样保留：非本 meshlet 资源永不动。
    require_ok(
        &netns_exec(
            &topo.a.netns,
            &["ip", "route", "add", "10.245.0.0/24", "dev", "wg0"],
        ),
        "plant an unmarked route on A's tunnel",
    );
    let decision = a_agent
        .reconcile(&mtu_plan)
        .expect("reconcile with a foreign route");
    assert!(
        !decision.needs_apply,
        "a foreign route is not drift: {:?}",
        decision.reason
    );
    let shown = String::from_utf8_lossy(
        &netns_exec(
            &topo.a.netns,
            &["ip", "route", "show", "exact", "10.245.0.0/24"],
        )
        .stdout,
    )
    .to_string();
    assert!(
        shown.contains("wg0"),
        "the foreign route must survive untouched: {shown}"
    );

    // (c) 网关上一条 Meshlet 所有权注释、但不在计划里的 NAT 规则（多余自有
    // 对象）→ KernelDrift 并按指纹清理；外来规则保留。
    gw_agent
        .reconcile(&gw_plan)
        .expect("gateway re-applies nat plan");
    require_ok(
        &netns_exec(
            &topo.gw.netns,
            &[
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-d",
                "203.0.113.0/24",
                "-j",
                "SNAT",
                "--to-source",
                "192.168.1.1",
                "-m",
                "comment",
                "--comment",
                ALIAS_OWNER,
            ],
        ),
        "plant an extra meshlet-owned nat rule",
    );
    let decision = gw_agent
        .reconcile(&gw_plan)
        .expect("reconcile after nat injection");
    assert!(decision.needs_apply, "an extra meshlet-owned rule is drift");
    assert_eq!(decision.reason, Reason::KernelDrift);
    let postrouting = topo.nat_rules(&topo.gw.netns, "POSTROUTING");
    assert!(
        !postrouting.contains("203.0.113.0/24"),
        "the extra meshlet-owned rule must be removed:\n{postrouting}"
    );
    assert!(
        postrouting.contains(ALIAS_OWNER),
        "the planned snat rule must survive:\n{postrouting}"
    );
    let prerouting = topo.nat_rules(&topo.gw.netns, "PREROUTING");
    assert!(
        prerouting.contains("user rule"),
        "the foreign rule must survive the fingerprint cleanup:\n{prerouting}"
    );
    assert!(
        !a_agent.reconcile(&mtu_plan).unwrap().needs_apply,
        "no drift left on A"
    );

    // teardown 并断言「跑完不留垃圾」（按本进程标签计，历史残留由
    // `preflight_cleanup` 负责）。
    drop(topo);
    let tag = tag("r");
    let netns_text = String::from_utf8_lossy(&sudo(&["ip", "netns", "list"]).stdout).to_string();
    let links_text = String::from_utf8_lossy(&sudo(&["ip", "-br", "link"]).stdout).to_string();
    assert_eq!(
        count_prefix_lines(&netns_text, &tag),
        0,
        "leftover netns after teardown:\n{netns_text}"
    );
    assert_eq!(
        count_prefix_lines(&links_text, &tag),
        0,
        "leftover links after teardown:\n{links_text}"
    );
    for dir in [a_dir, b_dir, gw_dir] {
        std::fs::remove_dir_all(dir).ok();
    }
}
