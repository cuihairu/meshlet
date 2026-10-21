//! Last-good state persistence and security-preserving recovery selection.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::model::{HubState, NetworkState, RevokedPeer};

pub trait LastGoodStore {
    fn load(&self) -> Result<Option<HubState>, String>;
    fn save(&self, state: &HubState) -> Result<(), String>;
}

#[derive(Debug, Default)]
pub struct MemoryLastGoodStore {
    value: Mutex<Option<HubState>>,
}

impl MemoryLastGoodStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn current(&self) -> Option<HubState> {
        self.value.lock().expect("last-good lock").clone()
    }
}

impl LastGoodStore for MemoryLastGoodStore {
    fn load(&self) -> Result<Option<HubState>, String> {
        Ok(self.current())
    }

    fn save(&self, state: &HubState) -> Result<(), String> {
        *self.value.lock().map_err(|_| "last-good lock poisoned")? = Some(state.clone());
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct FileLastGoodStore {
    path: PathBuf,
}

impl FileLastGoodStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl LastGoodStore for FileLastGoodStore {
    fn load(&self) -> Result<Option<HubState>, String> {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(format!("read {}: {error}", self.path.display()));
            }
        };
        serde_json::from_str(&raw)
            .map(Some)
            .map_err(|error| format!("parse {}: {error}", self.path.display()))
    }

    fn save(&self, state: &HubState) -> Result<(), String> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|error| format!("create {}: {error}", dir.display()))?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let body = serde_json::to_string_pretty(state).map_err(|error| error.to_string())?;
        std::fs::write(&tmp, body).map_err(|error| format!("write {}: {error}", tmp.display()))?;
        restrict_permissions(&tmp)?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|error| format!("rename into {}: {error}", self.path.display()))?;
        Ok(())
    }
}

fn restrict_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("chmod {}: {error}", path.display()))?;
    }
    Ok(())
}

/// Build the state a failed transition may restore.
///
/// This is intentionally not a verbatim copy of last-good:
/// - networks removed from desired state are not resurrected;
/// - revocation from both states wins over last-good peers;
/// - routes are retained only when a surviving peer still covers them.
pub fn recovery_state(last_good: &HubState, desired: &HubState) -> HubState {
    let desired_ids: BTreeSet<&str> = desired
        .networks
        .iter()
        .map(|network| network.network_id.as_str())
        .collect();

    let mut networks = Vec::new();
    for previous in &last_good.networks {
        if !desired_ids.contains(previous.network_id.as_str()) {
            continue;
        }
        let current = desired.network(&previous.network_id);
        networks.push(sanitize_network(previous, current));
    }

    HubState {
        revision: desired.revision,
        networks,
    }
}

fn sanitize_network(previous: &NetworkState, desired: Option<&NetworkState>) -> NetworkState {
    let mut network = previous.clone();
    if let Some(desired) = desired {
        network
            .revoked_peers
            .extend(desired.revoked_peers.iter().cloned());
    }

    let mut seen = BTreeSet::new();
    network
        .revoked_peers
        .retain(|revoked| seen.insert((revoked.public_key.clone(), revoked.overlay_ip)));
    let revoked_keys: BTreeSet<&str> = network
        .revoked_peers
        .iter()
        .map(|revoked| revoked.public_key.as_str())
        .collect();
    let revoked_ips: BTreeSet<_> = network
        .revoked_peers
        .iter()
        .map(|revoked: &RevokedPeer| revoked.overlay_ip)
        .collect();
    network.peers.retain(|peer| {
        !revoked_keys.contains(peer.public_key.as_str()) && !revoked_ips.contains(&peer.overlay_ip)
    });

    let allowed: Vec<_> = network
        .effective_peers()
        .into_iter()
        .flat_map(NetworkState::effective_allowed_ips)
        .collect();
    network.routes.retain(|route| {
        allowed
            .iter()
            .any(|cidr| cidr.contains_cidr(&route.destination))
    });
    network
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{PeerState, RouteState};

    pub fn network(id: &str) -> NetworkState {
        NetworkState {
            network_id: id.into(),
            interface: format!("wg-{id}"),
            listen_port: 51820,
            hub_address: "10.240.0.1".parse().unwrap(),
            prefix_len: 24,
            private_key_file: "/run/meshlet/hub.key".into(),
            mtu: None,
            peers: vec![],
            routes: vec![],
            revoked_peers: vec![],
        }
    }

    fn key(seed: char) -> String {
        let mut value: String = std::iter::repeat_n(seed, 43).collect();
        value.push('=');
        value
    }

    fn peer(device: &str, seed: char, ip: &str) -> PeerState {
        PeerState {
            device_id: device.into(),
            public_key: key(seed),
            overlay_ip: ip.parse().unwrap(),
            allowed_ips: vec!["192.168.1.0/24".parse().unwrap()],
            persistent_keepalive_secs: None,
        }
    }

    #[test]
    fn recovery_does_not_resurrect_revoked_peer_or_removed_network() {
        let mut previous = HubState {
            revision: 1,
            networks: vec![network("net-a"), network("net-b")],
        };
        let revoked = peer("dev-a", 'A', "10.240.0.2");
        previous.networks[0].peers.push(revoked.clone());
        previous.networks[0].routes.push(RouteState {
            destination: "192.168.1.0/24".parse().unwrap(),
        });

        let mut desired = network("net-a");
        desired.revoked_peers.push(RevokedPeer {
            public_key: revoked.public_key.clone(),
            overlay_ip: revoked.overlay_ip,
            reason: Some("revoked".into()),
        });
        let desired = HubState {
            revision: 2,
            networks: vec![desired],
        };

        let recovered = recovery_state(&previous, &desired);
        assert_eq!(recovered.networks.len(), 1);
        assert!(recovered.networks[0].peers.is_empty());
        assert!(recovered.networks[0].routes.is_empty());
        assert_eq!(recovered.networks[0].revoked_peers.len(), 1);
    }

    #[test]
    fn file_store_round_trips_and_missing_is_none() {
        let dir = std::env::temp_dir().join(format!("meshlet-r02-{}", std::process::id()));
        let path = dir.join("last-good.json");
        let store = FileLastGoodStore::new(&path);
        assert_eq!(store.load().unwrap(), None);
        let state = HubState {
            revision: 9,
            networks: vec![network("net-a")],
        };
        store.save(&state).unwrap();
        assert_eq!(store.load().unwrap(), Some(state));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
