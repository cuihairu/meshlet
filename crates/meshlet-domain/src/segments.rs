//! Segment trust-group entities and membership predicates (ADR-012).

use crate::cidr::Ipv4Cidr;
use crate::entities::{NetworkId, SegmentGrantId, SegmentId, Timestamp};

/// Canonical id for a network's built-in default segment.
/// Keep in sync with the SQL migrations (`'seg-' || network_id`).
pub fn default_segment_id(network_id: &NetworkId) -> SegmentId {
    SegmentId(format!("seg-{network_id}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentStatus {
    Active,
    Quarantined,
}

impl SegmentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "active" => Some(Self::Active),
            "quarantined" => Some(Self::Quarantined),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentGrantStatus {
    Pending,
    Applied,
    Revoked,
}

impl SegmentGrantStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "applied" => Some(Self::Applied),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

pub struct SegmentGrantBuilder {
    id: SegmentGrantId,
    network_id: NetworkId,
    source_segment_id: SegmentId,
    destination_segment_id: SegmentId,
    created_at: Timestamp,
}

impl SegmentGrantBuilder {
    pub fn new(
        id: SegmentGrantId,
        network_id: NetworkId,
        source_segment_id: SegmentId,
        destination_segment_id: SegmentId,
        created_at: Timestamp,
    ) -> Self {
        Self {
            id,
            network_id,
            source_segment_id,
            destination_segment_id,
            created_at,
        }
    }

    pub fn build(self) -> SegmentGrant {
        SegmentGrant {
            id: self.id,
            network_id: self.network_id,
            source_segment_id: self.source_segment_id,
            destination_segment_id: self.destination_segment_id,
            status: SegmentGrantStatus::Pending,
            created_at: self.created_at,
            revoked_at: None,
        }
    }
}

impl SegmentGrant {
    pub fn revoke(&mut self, now: Timestamp) -> Result<(), &'static str> {
        if self.status == SegmentGrantStatus::Revoked {
            return Err("segment grant is already revoked");
        }
        self.status = SegmentGrantStatus::Revoked;
        self.revoked_at = Some(now);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub id: SegmentId,
    pub network_id: NetworkId,
    pub name: String,
    pub cidr: Ipv4Cidr,
    pub status: SegmentStatus,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentGrant {
    pub id: SegmentGrantId,
    pub network_id: NetworkId,
    pub source_segment_id: SegmentId,
    pub destination_segment_id: SegmentId,
    pub status: SegmentGrantStatus,
    pub created_at: Timestamp,
    pub revoked_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SegmentError {
    #[error("segment {segment} is outside overlay {overlay}")]
    OutsideOverlay {
        segment: Ipv4Cidr,
        overlay: Ipv4Cidr,
    },
    #[error("non-default segment cannot equal overlay {segment}")]
    OverlayEqualNonDefault { segment: Ipv4Cidr },
    #[error("device {device} is outside network {network}")]
    DeviceOutsideNetwork {
        device: std::net::Ipv4Addr,
        network: Ipv4Cidr,
    },
    #[error("segment {segment} belongs to another network {network}")]
    CrossNetworkSegment {
        segment: SegmentId,
        network: NetworkId,
    },
    #[error("device {device} is outside segment {segment}")]
    DeviceOutsideSegment {
        device: std::net::Ipv4Addr,
        segment: Ipv4Cidr,
    },
}

impl Segment {
    pub fn validate_cidr(&self, overlay: Ipv4Cidr) -> Result<(), SegmentError> {
        let is_default = self.name == "default";
        if is_default && self.cidr != overlay {
            return Err(SegmentError::OutsideOverlay {
                segment: self.cidr,
                overlay,
            });
        }
        if !overlay.contains_cidr(&self.cidr) {
            return Err(SegmentError::OutsideOverlay {
                segment: self.cidr,
                overlay,
            });
        }
        if !is_default && self.cidr == overlay {
            return Err(SegmentError::OverlayEqualNonDefault { segment: self.cidr });
        }
        Ok(())
    }
}

/// Validate that a device is a member of this network's assigned segment.
/// Segment membership implies overlay membership; the segment id must also
/// belong to the same network so persisted state cannot bridge networks.
pub fn validate_device_segment(
    address: std::net::Ipv4Addr,
    network_id: &NetworkId,
    segment_id: &SegmentId,
    overlay: Ipv4Cidr,
    segments: &[Segment],
) -> Result<(), SegmentError> {
    let segment = segments
        .iter()
        .find(|segment| &segment.id == segment_id)
        .ok_or_else(|| SegmentError::DeviceOutsideSegment {
            device: address,
            segment: segments
                .first()
                .map(|segment| segment.cidr)
                .unwrap_or_else(|| "0.0.0.0/32".parse().unwrap()),
        })?;
    if !segment.cidr.contains(address) {
        return Err(SegmentError::DeviceOutsideSegment {
            device: address,
            segment: segment.cidr,
        });
    }
    if segment.network_id != *network_id {
        return Err(SegmentError::CrossNetworkSegment {
            segment: segment.id.clone(),
            network: network_id.clone(),
        });
    }
    if !overlay.contains(address) {
        return Err(SegmentError::DeviceOutsideNetwork {
            device: address,
            network: overlay,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::SegmentGrantId;

    fn segment(name: &str, cidr: &str) -> Segment {
        Segment {
            id: SegmentId(format!("seg-{name}")),
            network_id: NetworkId("net-1".into()),
            name: name.into(),
            cidr: cidr.parse().unwrap(),
            status: SegmentStatus::Active,
            created_at: "2026-10-17T00:00:00Z".into(),
        }
    }

    #[test]
    fn default_segment_id_is_stable_and_network_scoped() {
        assert_eq!(
            default_segment_id(&NetworkId("net-12".into())),
            SegmentId("seg-net-12".into())
        );
        assert_ne!(
            default_segment_id(&NetworkId("net-12".into())),
            default_segment_id(&NetworkId("net-13".into()))
        );
    }

    #[test]
    fn segment_statuses_and_grant_statuses_have_exact_persistence_encoding() {
        assert_eq!(SegmentStatus::Active.as_str(), "active");
        assert_eq!(SegmentStatus::Quarantined.as_str(), "quarantined");
        assert_eq!(
            SegmentStatus::parse(" active \n"),
            Some(SegmentStatus::Active)
        );
        assert_eq!(
            SegmentStatus::parse("quarantined"),
            Some(SegmentStatus::Quarantined)
        );
        assert_eq!(SegmentStatus::parse("disabled"), None);

        assert_eq!(SegmentGrantStatus::Pending.as_str(), "pending");
        assert_eq!(SegmentGrantStatus::Applied.as_str(), "applied");
        assert_eq!(SegmentGrantStatus::Revoked.as_str(), "revoked");
        assert_eq!(
            SegmentGrantStatus::parse("pending"),
            Some(SegmentGrantStatus::Pending)
        );
        assert_eq!(
            SegmentGrantStatus::parse("applied"),
            Some(SegmentGrantStatus::Applied)
        );
        assert_eq!(
            SegmentGrantStatus::parse("revoked"),
            Some(SegmentGrantStatus::Revoked)
        );
        assert_eq!(SegmentGrantStatus::parse("issued"), None);
    }

    #[test]
    fn default_segment_may_equal_overlay_but_user_segment_may_not() {
        let overlay = "10.240.0.0/16".parse().unwrap();
        assert!(segment("default", "10.240.0.0/16")
            .validate_cidr(overlay)
            .is_ok());
        assert!(segment("users", "10.240.1.0/24")
            .validate_cidr(overlay)
            .is_ok());
        assert!(matches!(
            segment("users", "10.240.0.0/16").validate_cidr(overlay),
            Err(SegmentError::OverlayEqualNonDefault { .. })
        ));
    }

    #[test]
    fn segment_containment_and_default_rules_use_exact_boundaries() {
        let overlay = "10.240.0.0/16".parse().unwrap();
        assert!(segment("users", "10.240.0.0/14")
            .validate_cidr(overlay)
            .is_err());
        assert!(segment("users", "10.240.0.0/15")
            .validate_cidr(overlay)
            .is_err());
        assert!(segment("users", "10.240.0.0/16")
            .validate_cidr(overlay)
            .is_err());
        assert!(segment("users", "10.240.255.0/24")
            .validate_cidr(overlay)
            .is_ok());
        assert!(segment("users", "10.241.0.0/24")
            .validate_cidr(overlay)
            .is_err());
        assert!(segment("default", "10.240.0.0/24")
            .validate_cidr(overlay)
            .is_err());
    }

    #[test]
    fn device_must_belong_to_assigned_segment() {
        let segments = [segment("users", "10.240.1.0/24")];
        let id = segments[0].id.clone();
        let network = NetworkId("net-1".into());
        let overlay = "10.240.0.0/16".parse().unwrap();
        assert!(validate_device_segment(
            "10.240.1.9".parse().unwrap(),
            &network,
            &id,
            overlay,
            &segments
        )
        .is_ok());
        assert!(validate_device_segment(
            "10.240.2.9".parse().unwrap(),
            &network,
            &id,
            overlay,
            &segments
        )
        .is_err());
    }

    #[test]
    fn missing_device_segment_reports_zero_host_fallback() {
        let error = validate_device_segment(
            "10.240.1.9".parse().unwrap(),
            &NetworkId("net-1".into()),
            &SegmentId("seg-missing".into()),
            "10.240.0.0/16".parse().unwrap(),
            &[],
        )
        .unwrap_err();
        assert!(matches!(
            error,
            SegmentError::DeviceOutsideSegment { segment, .. }
                if segment == "0.0.0.0/32".parse().unwrap()
        ));
    }

    #[test]
    fn device_assignment_rejects_cross_network_segment_and_overlay_escape() {
        let network = NetworkId("net-1".into());
        let overlay = "10.240.0.0/16".parse().unwrap();
        let mut foreign = segment("users", "10.241.1.0/24");
        foreign.network_id = NetworkId("net-2".into());
        let id = foreign.id.clone();
        assert!(matches!(
            validate_device_segment(
                "10.241.1.9".parse().unwrap(),
                &network,
                &id,
                overlay,
                &[foreign]
            ),
            Err(SegmentError::CrossNetworkSegment { .. })
        ));

        let local = segment("users", "10.240.1.0/24");
        let id = local.id.clone();
        assert!(matches!(
            validate_device_segment(
                "10.240.1.9".parse().unwrap(),
                &network,
                &id,
                "10.241.0.0/16".parse().unwrap(),
                &[local]
            ),
            Err(SegmentError::DeviceOutsideNetwork { .. })
        ));
    }

    #[test]
    fn grant_is_directional_by_construction() {
        let source = segment("a", "10.240.1.0/24");
        let destination = segment("b", "10.240.2.0/24");
        let grant = SegmentGrant {
            id: SegmentGrantId("grant-1".into()),
            network_id: source.network_id.clone(),
            source_segment_id: source.id,
            destination_segment_id: destination.id,
            status: SegmentGrantStatus::Pending,
            created_at: "2026-10-17T00:00:00Z".into(),
            revoked_at: None,
        };
        assert_eq!(grant.source_segment_id, SegmentId("seg-a".into()));
        assert_eq!(grant.destination_segment_id, SegmentId("seg-b".into()));
    }
}
