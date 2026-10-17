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
        match value {
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
    #[error("device {device} is outside segment {segment}")]
    DeviceOutsideSegment {
        device: std::net::Ipv4Addr,
        segment: Ipv4Cidr,
    },
}

impl Segment {
    pub fn validate_cidr(&self, overlay: Ipv4Cidr) -> Result<(), SegmentError> {
        if !overlay.overlaps(&self.cidr) {
            return Err(SegmentError::OutsideOverlay {
                segment: self.cidr,
                overlay,
            });
        }
        if self.cidr == overlay && self.name != "default" {
            return Err(SegmentError::OverlayEqualNonDefault { segment: self.cidr });
        }
        Ok(())
    }
}

/// Validate that a member address belongs to its assigned segment.
pub fn validate_device_segment(
    address: std::net::Ipv4Addr,
    segment_id: &SegmentId,
    segments: &[Segment],
) -> Result<(), SegmentError> {
    let segment = segments.iter().find(|segment| &segment.id == segment_id);
    if segment.is_some_and(|segment| segment.cidr.contains(address)) {
        Ok(())
    } else {
        Err(SegmentError::DeviceOutsideSegment {
            device: address,
            segment: segment
                .map(|segment| segment.cidr)
                .unwrap_or("0.0.0.0/32".parse().unwrap()),
        })
    }
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
    fn device_must_belong_to_assigned_segment() {
        let segments = [segment("users", "10.240.1.0/24")];
        let id = segments[0].id.clone();
        assert!(validate_device_segment("10.240.1.9".parse().unwrap(), &id, &segments).is_ok());
        assert!(validate_device_segment("10.240.2.9".parse().unwrap(), &id, &segments).is_err());
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
