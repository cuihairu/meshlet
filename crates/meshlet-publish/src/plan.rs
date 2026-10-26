use crate::dns::DnsRecord;
use crate::forwarding::PortForwardConfig;
use crate::health::{HealthState, ProbeTarget};
use crate::http::HttpRouteSet;
use std::net::SocketAddr;
use std::time::Duration;

/// Desired publish state for one device.
///
/// This is the configuration segment the control plane pushes inside
/// `DevicePlan` and the agent reconciles on the device. It carries typed
/// objects only: the runtime never executes commands or shell fragments.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublishPlan {
    /// L4 port forwards bound on this device.
    #[serde(default)]
    pub forwards: Vec<PortForwardConfig>,
    /// Listener the HTTP(S) router binds; `None` = no HTTP router.
    #[serde(default)]
    pub http_listener: Option<SocketAddr>,
    /// HTTP(S) routes terminating on this device.
    #[serde(default)]
    pub http_routes: HttpRouteSet,
    /// Split-horizon DNS catalog bound on this device.
    #[serde(default)]
    pub dns: Option<DnsPlan>,
    /// Health probes to run on this device and report back to the control
    /// plane.
    #[serde(default)]
    pub probes: Vec<ProbeSchedule>,
}

impl PublishPlan {
    /// No listener of any kind is wanted.
    pub fn is_empty(&self) -> bool {
        self.forwards.is_empty()
            && self.http_listener.is_none()
            && self.http_routes.routes().is_empty()
            && self.dns.is_none()
            && self.probes.is_empty()
    }

    /// Validate every object in the plan. Called by the control plane before
    /// persistence and by the agent before reconciling.
    pub fn validate(&self) -> Result<(), crate::PublishError> {
        for forward in &self.forwards {
            forward.validate()?;
        }
        for schedule in &self.probes {
            schedule.validate()?;
        }
        if self.http_routes.routes().is_empty() != self.http_listener.is_none() {
            return Err(crate::PublishError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "http routes and http_listener must be present together",
            )));
        }
        Ok(())
    }
}

/// Split-horizon DNS deployment: where to bind, which suffix to answer, and
/// what to answer with. Records stay inside `internal_suffix` (enforced by
/// [`crate::dns::DnsCatalog`]); public DNS resolution is never overridden.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DnsPlan {
    pub network_id: String,
    pub internal_suffix: String,
    pub bind_address: SocketAddr,
    #[serde(default)]
    pub records: Vec<DnsRecord>,
}

impl DnsPlan {
    /// Probe targets are validated by the runtime; DNS plans validate through
    /// [`crate::dns::DnsCatalog`], so only structural sanity is checked here.
    pub fn validate(&self) -> Result<(), crate::PublishError> {
        if self.bind_address.port() == 0 {
            return Err(invalid("dns bind address must not use port 0"));
        }
        if self.internal_suffix.trim().is_empty() {
            return Err(invalid("dns internal suffix must not be empty"));
        }
        Ok(())
    }
}

/// One probe plus the cadence at which the agent runs it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProbeSchedule {
    pub id: String,
    pub target: ProbeTarget,
    pub interval: Duration,
}

impl ProbeSchedule {
    /// A zero cadence would pin a core; the control plane enforces a floor
    /// but the runtime must not accept one either.
    pub fn validate(&self) -> Result<(), crate::PublishError> {
        if self.id.trim().is_empty() {
            return Err(invalid("probe id must not be empty"));
        }
        if self.interval.is_zero() {
            return Err(invalid("probe interval must not be zero"));
        }
        Ok(())
    }
}

/// One probe result as the agent reports it back to the control plane.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProbeReport {
    pub probe_id: String,
    pub state: HealthState,
    /// RFC-3339 UTC timestamp of the probe run.
    pub checked_at: String,
    pub detail: Option<String>,
}

fn invalid(message: impl Into<String>) -> crate::PublishError {
    crate::PublishError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_plan_reports_empty_and_validates() {
        let plan = PublishPlan::default();
        assert!(plan.is_empty());
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn routes_without_a_listener_fail_validation() {
        let mut plan = PublishPlan::default();
        let route = crate::http::HttpRoute {
            id: "hr-1".into(),
            network_id: "net-1".into(),
            hostname: "app.mesh".into(),
            path_prefix: "/".into(),
            backend_address: "127.0.0.1:8080".parse().unwrap(),
            policy: Default::default(),
            tls_passthrough: false,
        };
        plan.http_routes = HttpRouteSet::new(vec![route]).unwrap();
        assert!(!plan.is_empty());
        assert!(plan.validate().is_err(), "routes need a listener");
        plan.http_listener = Some("0.0.0.0:443".parse().unwrap());
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn probe_schedule_rejects_zero_interval() {
        let mut schedule = ProbeSchedule {
            id: "pb-1".into(),
            target: ProbeTarget::Tcp {
                address: "127.0.0.1:8080".parse().unwrap(),
                timeout: Duration::from_secs(1),
            },
            interval: Duration::ZERO,
        };
        assert!(schedule.validate().is_err());
        schedule.interval = Duration::from_millis(50);
        assert!(schedule.validate().is_ok());
    }

    #[test]
    fn dns_plan_rejects_port_zero() {
        let mut plan = DnsPlan {
            network_id: "net-1".into(),
            internal_suffix: "mesh".into(),
            bind_address: "0.0.0.0:0".parse().unwrap(),
            records: Vec::new(),
        };
        assert!(plan.validate().is_err());
        plan.bind_address = "127.0.0.1:5353".parse().unwrap();
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn plan_round_trips_through_json() {
        let plan = PublishPlan {
            forwards: vec![PortForwardConfig {
                id: "pf-1".into(),
                network_id: "net-1".into(),
                protocol: crate::ForwardProtocol::Tcp,
                listener_address: "0.0.0.0:9000".parse().unwrap(),
                backend_address: "192.168.1.10:9000".parse().unwrap(),
                policy: Default::default(),
                enabled: true,
            }],
            http_listener: Some("0.0.0.0:8443".parse().unwrap()),
            http_routes: HttpRouteSet::new(vec![crate::HttpRoute {
                id: "hr-1".into(),
                network_id: "net-1".into(),
                hostname: "app.mesh".into(),
                path_prefix: "/".into(),
                backend_address: "192.168.1.10:8080".parse().unwrap(),
                policy: Default::default(),
                tls_passthrough: false,
            }])
            .unwrap(),
            dns: Some(DnsPlan {
                network_id: "net-1".into(),
                internal_suffix: "mesh".into(),
                bind_address: "0.0.0.0:5353".parse().unwrap(),
                records: vec![DnsRecord {
                    service_id: "svc-1".into(),
                    name: "app.mesh".into(),
                    address: "192.168.1.10".parse().unwrap(),
                    ttl: 60,
                    priority: 10,
                }],
            }),
            probes: vec![ProbeSchedule {
                id: "pb-1".into(),
                target: ProbeTarget::Tcp {
                    address: "127.0.0.1:9000".parse().unwrap(),
                    timeout: Duration::from_secs(2),
                },
                interval: Duration::from_secs(30),
            }],
        };
        let body = serde_json::to_string(&plan).unwrap();
        let back: PublishPlan = serde_json::from_str(&body).unwrap();
        assert_eq!(plan, back);
        assert!(back.validate().is_ok());
        assert!(!back.is_empty());
    }
}
