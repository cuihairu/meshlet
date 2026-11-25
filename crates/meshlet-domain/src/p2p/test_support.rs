//! Test fixtures shared across sub-modules (compiled only under cfg(test)): common
//! network segment constants and endpoint/cidr constructors.

use crate::cidr::Ipv4Cidr;
use crate::p2p::endpoint::EndpointCandidate;

pub const OVERLAY: &str = "10.240.0.0/16";
pub const HOME: &str = "192.168.1.0/24";

pub fn lan(ip: &str, port: u16) -> EndpointCandidate {
    EndpointCandidate::lan(ip.parse().unwrap(), port)
}

pub fn public(ip: &str, port: u16) -> EndpointCandidate {
    EndpointCandidate::public(ip.parse().unwrap(), port)
}

pub fn cidr(s: &str) -> Ipv4Cidr {
    s.parse().unwrap()
}
