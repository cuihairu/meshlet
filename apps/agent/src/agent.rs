//! Agent 主体：拉计划 → 对账 → 应用 → 心跳，循环之。
//!
//! 一切内核操作都经 [`meshlet_network::linux::LinuxNetworkBackend`]（ADR-007）：
//! 本模块只负责**何时**调用它与**喂什么配置**（计划来自 server，绝非本地拼装
//! 的 Shell 命令，§16.4）。

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use meshlet_config::{AgentConfig, DataplaneConfig};
use meshlet_domain::DataplaneEvidence;
use meshlet_network::linux::LinuxNetworkBackend;
use meshlet_network::{DevicePlan, DEFAULT_TUNNEL_MTU};

use crate::reconcile::{needs_apply, stale_owners, state_path, AgentState, Decision};
use crate::server;

/// 拉取持续失败时的退避上限（秒）：服务端不可达时不打满日志。
pub const BACKOFF_MAX_SECS: u64 = 300;
/// 连续成功后的正常轮询间隔由 `[dataplane] poll_interval_secs` 决定。
const BACKOFF_MIN_SECS: u64 = 1;

/// 设备端 agent：拉计划 → 对账 → 应用 → 心跳，循环之。
pub struct Agent {
    server_url: String,
    token: String,
    dataplane: DataplaneConfig,
    backend: LinuxNetworkBackend,
    private_key: Option<String>,
    /// 账本状态文件（`{state_dir}/applied.json`）。
    state_path: std::path::PathBuf,
}

impl Agent {
    /// 生产构造：默认 `sudo -n` 后端（agent 通常以 root 运行；`sudo -n` 在
    /// 已是 root 或已免密的环境下同样成立）。
    pub fn new(config: AgentConfig, private_key: Option<String>) -> Self {
        let backend = LinuxNetworkBackend::new()
            .with_interface(config.dataplane.interface.clone())
            .with_sudo();
        Self::with_backend(config, private_key, backend)
    }

    /// 注入后端（netns 集成测试用；生产走 [`Agent::new`]）。
    pub fn with_backend(
        config: AgentConfig,
        private_key: Option<String>,
        backend: LinuxNetworkBackend,
    ) -> Self {
        Self {
            server_url: config.server_url,
            token: config.device_token.unwrap_or_default(),
            state_path: state_path(&config.state_dir),
            dataplane: config.dataplane,
            private_key,
            backend,
        }
    }

    /// 账本状态文件路径（测试与运维排查用）。
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// 主循环：首轮即对账（启动对账），之后按 `poll_interval_secs` 轮询；
    /// 连续失败指数退避至上限。
    pub fn run(self) -> ! {
        let mut backoff = Duration::from_secs(BACKOFF_MIN_SECS);
        loop {
            match self.tick() {
                Ok(()) => backoff = Duration::from_secs(BACKOFF_MIN_SECS),
                Err(e) => {
                    tracing::warn!(error = %e, retry_in_secs = backoff.as_secs(), "agent tick failed");
                }
            }
            let wait = if backoff <= Duration::from_secs(BACKOFF_MIN_SECS) {
                Duration::from_secs(self.dataplane.poll_interval_secs.max(1))
            } else {
                backoff
            };
            std::thread::sleep(wait);
            backoff = (backoff * 2).min(Duration::from_secs(BACKOFF_MAX_SECS));
        }
    }

    /// 一轮：拉计划 → 需要则应用 → 心跳上报。
    pub fn tick(&self) -> Result<(), String> {
        let plan = server::fetch_plan(&self.server_url, &self.token)?;
        self.reconcile(&plan)?;
        if let Err(e) = self.heartbeat(Some(&plan)) {
            // 上报失败不影响数据面：计划已按期望对账完毕。
            tracing::warn!(error = %e, "heartbeat not delivered");
        }
        Ok(())
    }

    /// 对账并按需重放（§10.1 + TODO #32）。
    ///
    /// 拉不到计划时**不动内核**：数据面以服务端期望为唯一来源，宁可不改也不
    /// 按猜测重放（调用方 [`Agent::tick`] 因此让整轮失败并退避重试）。
    pub fn reconcile(&self, plan: &DevicePlan) -> Result<Decision, String> {
        let state = AgentState::load(&self.state_path).unwrap_or_default();
        let snapshot = self
            .backend
            .inspect_sync()
            .map_err(|e| format!("inspect the local network state: {e}"))?;
        let decision = needs_apply(&state, &snapshot, plan);
        if !decision.needs_apply {
            return Ok(decision);
        }
        // 先按所有权清理计划里已消失的映射单元（§12.6），再重放隧道/路由/NAT。
        for owner in stale_owners(&state, plan) {
            self.backend
                .remove_nat_sync(&owner)
                .map_err(|e| format!("remove meshlet nat rules of {owner}: {e}"))?;
            tracing::info!(owner = %owner, "removed stale meshlet nat rules");
        }
        // hub 入口地址兜底（§16.4：服务端不下发 agent 的网络位置）：计划未带
        // endpoint 时用本地 `[dataplane] hub_endpoint` 填充——只影响本次内核下
        // 发，账本仍按服务端原计划记（desired_config_hash 不因此变化）。
        let local_plan = plan_with_hub_endpoint(plan, self.dataplane.hub_endpoint.as_deref());
        self.backend
            .apply_device_plan_sync(&local_plan, self.private_key.clone(), None)
            .map_err(|e| format!("apply the desired plan: {e}"))?;
        AgentState::from_plan(plan).save(&self.state_path)?;
        tracing::info!(
            desired_config_hash = %plan.desired_config_hash,
            routes = plan.routes.len(),
            nat_rules = plan.nat_rules.len(),
            reason = ?decision.reason,
            "applied the desired device plan"
        );
        Ok(decision)
    }

    /// 心跳上报（§12.4/§14.1）：带本地读到的最近握手时间 + 数据面实测证据
    /// （§7.5：内核读数 + 计划 MTU 大包探测）。
    pub fn heartbeat(&self, plan: Option<&DevicePlan>) -> Result<(), String> {
        let evidence = self.collect_evidence(plan);
        server::heartbeat(
            &self.server_url,
            &self.token,
            self.last_handshake(),
            Some(evidence),
        )
        .map(|_| ())
        .map_err(|e| format!("heartbeat failed: {e}"))
    }

    /// 数据面实测证据（§7.5）：内核读数 + 大包探测。读数失败按 `None` 上报
    /// （证据缺失可见），绝不臆测默认值——探测失败与未探测在服务端同形，
    /// 都按「未证实」处理。
    pub fn collect_evidence(&self, plan: Option<&DevicePlan>) -> DataplaneEvidence {
        let snapshot = self.backend.inspect_sync().ok();
        DataplaneEvidence {
            tunnel_mtu: snapshot.as_ref().and_then(|s| s.tunnel_mtu),
            nat_rules_present: snapshot.as_ref().map(|s| s.nat_rules_present),
            mtu_probe_payload: plan.and_then(|p| {
                let (target, payload) = probe_decision(p)?;
                self.backend
                    .mtu_probe_sync(target, payload)
                    .then_some(payload)
            }),
        }
    }

    /// `wg show <if> latest-handshakes` → 最近握手时刻（ISO-8601）；取不到则
    /// 省略（服务端按「未取到」处理，不虚构在线证据）。
    fn last_handshake(&self) -> Option<String> {
        let out = std::process::Command::new("wg")
            .args(["show", &self.dataplane.interface, "latest-handshakes"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let ts: i64 = text
            .split_whitespace()
            .filter_map(|t| t.parse().ok())
            .filter(|t| *t > 0)
            .max()?;
        chrono::DateTime::from_timestamp(ts, 0).map(|d| d.to_rfc3339())
    }
}

/// 本设备私钥（ADR-010：只在本机文件里，服务端永不携带；未配置则保留接口现有私钥）。
pub fn read_private_key(dp: &DataplaneConfig) -> Result<Option<String>, String> {
    let Some(path) = dp
        .private_key_file
        .as_deref()
        .filter(|p| !p.trim().is_empty())
    else {
        return Ok(None);
    };
    let raw =
        std::fs::read_to_string(path).map_err(|e| format!("read private_key_file {path}: {e}"))?;
    let key = raw.trim().to_string();
    if key.is_empty() {
        return Err(format!("private_key_file {path} is empty"));
    }
    Ok(Some(key))
}

/// 大包探测决策（纯逻辑）：目标 = hub 的 overlay 地址（自 ping 不经过隧道，
/// 证据失真，跳过）；载荷 = 计划 MTU − 28B（IP 头 20B + ICMP 头 8B），
/// 计划未配置 MTU 按默认 1420。hub 未知或载荷为 0 则不探测。
fn probe_decision(plan: &DevicePlan) -> Option<(Ipv4Addr, u32)> {
    let hub = plan.hub_address.filter(|h| *h != plan.tunnel.address)?;
    let payload = plan
        .tunnel
        .mtu
        .unwrap_or(DEFAULT_TUNNEL_MTU)
        .saturating_sub(28);
    (payload > 0).then_some((hub, payload))
}

/// hub 入口地址兜底（纯逻辑，§16.4）：服务端不知道 agent 的网络位置，计划里
/// hub peer 的 endpoint 为 `None`；agent 用本地 `[dataplane] hub_endpoint`
///（`host:port`）填充，设备才能主动发起握手。服务端已带值（未来通告
/// advertise endpoint）则尊重服务端，不覆盖；未配置兜底则原样返回。
fn plan_with_hub_endpoint(plan: &DevicePlan, hub_endpoint: Option<&str>) -> DevicePlan {
    let mut local = plan.clone();
    if let (Some(endpoint), Some(peer)) = (hub_endpoint, local.tunnel.peers.first_mut()) {
        if peer.endpoint.is_none() {
            peer.endpoint = Some(endpoint.to_string());
        }
    }
    local
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(state_dir: &str) -> AgentConfig {
        AgentConfig {
            server_url: "http://127.0.0.1:1".into(),
            state_dir: state_dir.into(),
            device_token: Some("tok".into()),
            dataplane: DataplaneConfig {
                enabled: true,
                ..DataplaneConfig::default()
            },
        }
    }

    #[test]
    fn private_key_is_read_trimmed_and_absent_is_ok() {
        // 未配置私钥：None（保留接口现有私钥，幂等重放）。
        assert_eq!(read_private_key(&DataplaneConfig::default()).unwrap(), None);

        let dir = std::env::temp_dir().join("meshlet-agent-key-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dev.key");
        std::fs::write(&path, "key-material\n").unwrap();
        let dp = DataplaneConfig {
            private_key_file: Some(path.to_string_lossy().to_string()),
            ..DataplaneConfig::default()
        };
        assert_eq!(
            read_private_key(&dp).unwrap().as_deref(),
            Some("key-material")
        );

        // 空文件：明确报错，不当“没配”处理（首装必然握手失败）。
        std::fs::write(&path, "\n").unwrap();
        assert!(read_private_key(&dp).is_err());

        // 缺失文件：路径写错必须可见。
        let missing = DataplaneConfig {
            private_key_file: Some("/nonexistent/meshlet/dev.key".into()),
            ..DataplaneConfig::default()
        };
        assert!(read_private_key(&missing).is_err());

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn state_path_lives_under_the_configured_state_dir() {
        let agent = Agent::new(config("/var/lib/meshlet"), None);
        assert_eq!(
            agent.state_path(),
            Path::new("/var/lib/meshlet/applied.json")
        );
    }

    #[test]
    fn heartbeat_against_a_dead_server_fails_visibly() {
        // 拉不到服务端时报错（可见），而不是静默「成功」——tick 据此退避重试。
        let agent = Agent::new(config("/tmp/meshlet-agent-dead"), None);
        let err = agent.heartbeat(None).expect_err("dead server");
        assert!(!err.is_empty(), "failure must be reported: {err}");
    }

    fn probe_plan(mtu: Option<u32>, hub: Option<&str>, own: &str) -> DevicePlan {
        DevicePlan {
            tunnel: meshlet_network::TunnelConfig {
                name: "wg0".into(),
                address: own.parse().unwrap(),
                address_prefix: 16,
                listen_port: None,
                peers: vec![],
                mtu,
                private_key: None,
            },
            routes: vec![],
            nat_rules: vec![],
            hub_address: hub.map(|h| h.parse().unwrap()),
            desired_config_hash: "hash".into(),
        }
    }

    #[test]
    fn hub_endpoint_fills_a_plan_without_one() {
        // 服务端计划不携带 endpoint（§16.4：服务端不知道 agent 的网络位置）。
        let mut p = probe_plan(None, Some("10.240.0.1"), "10.240.0.7");
        p.tunnel.peers.push(meshlet_network::PeerConfig {
            public_key: "hub-pub".into(),
            allowed_ips: vec!["10.240.0.0/16".parse().unwrap()],
            endpoint: None,
            persistent_keepalive_secs: None,
        });

        // 本地兜底填充 → 设备可主动发起握手。
        let filled = plan_with_hub_endpoint(&p, Some("10.98.0.10:51820"));
        assert_eq!(
            filled.tunnel.peers[0].endpoint.as_deref(),
            Some("10.98.0.10:51820")
        );
        // 哈希不被本地兜底改写：账本与漂移判定仍以服务端期望为准。
        assert_eq!(filled.desired_config_hash, p.desired_config_hash);

        // 服务端已带值（未来通告 advertise endpoint）→ 尊重服务端，不覆盖。
        let mut explicit = p.clone();
        explicit.tunnel.peers[0].endpoint = Some("10.98.0.99:51820".into());
        assert_eq!(
            plan_with_hub_endpoint(&explicit, Some("10.98.0.10:51820"))
                .tunnel
                .peers[0]
                .endpoint,
            explicit.tunnel.peers[0].endpoint
        );

        // 未配置兜底 → 原样返回；空 peer 计划不越界。
        assert_eq!(
            plan_with_hub_endpoint(&p, None).tunnel.peers[0].endpoint,
            None
        );
        let empty = probe_plan(None, None, "10.240.0.7");
        assert_eq!(
            plan_with_hub_endpoint(&empty, Some("10.98.0.10:51820"))
                .tunnel
                .peers
                .len(),
            0
        );
    }

    #[test]
    fn probe_decision_targets_the_hub_with_the_planned_payload() {
        let p = probe_plan(Some(1380), Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(
            probe_decision(&p),
            Some(("10.240.0.1".parse().unwrap(), 1352))
        );

        // 计划未配置 MTU：按默认 1420 探测（1420 − 28 = 1392）。
        let p = probe_plan(None, Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(
            probe_decision(&p),
            Some(("10.240.0.1".parse().unwrap(), 1392))
        );

        // hub 未知 / hub 就是自己（自 ping 不经过隧道）/ 载荷为 0：不探测。
        let p = probe_plan(Some(1380), None, "10.240.0.7");
        assert_eq!(probe_decision(&p), None);
        let p = probe_plan(Some(1380), Some("10.240.0.7"), "10.240.0.7");
        assert_eq!(probe_decision(&p), None);
        let p = probe_plan(Some(28), Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(probe_decision(&p), None);
    }
}
