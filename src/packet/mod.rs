pub mod ethernet;
pub mod ip;
pub mod tcp;
pub mod udp;
pub mod icmp;

use std::net::SocketAddr;

/// Packet Capture information
#[derive(Clone, Debug, PartialEq)]
pub struct CaptureInfo {
    /// Capture number
    pub capture_no: usize,
    /// Capture datetime
    pub datatime: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TcpIpFingerprint {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub ip_fingerprint: ip::IpFingerprint,
    pub tcp_fingerprint: Option<tcp::TcpFingerprint>,
    pub udp_fingerprint: Option<udp::UdpFingerprint>,
    pub icmp_fingerprint: Option<icmp::IcmpFingerprint>,
    pub icmpv6_fingerprint: Option<icmp::Icmpv6Fingerprint>,
    pub capture_info: CaptureInfo,
}
