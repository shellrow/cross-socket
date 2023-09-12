use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum IpNextLevelProtocol {
    Icmp,
    Icmpv6,
    Tcp,
    Udp,
    Unknown(u8),
}

impl IpNextLevelProtocol {
    pub fn number(&self) -> u8 {
        match *self {
            IpNextLevelProtocol::Icmp => 1,
            IpNextLevelProtocol::Icmpv6 => 58,
            IpNextLevelProtocol::Tcp => 6,
            IpNextLevelProtocol::Udp => 17,
            IpNextLevelProtocol::Unknown(n) => n,
        }
    }
    pub fn id(&self) -> String {
        match *self {
            IpNextLevelProtocol::Icmp => String::from("icmp"),
            IpNextLevelProtocol::Icmpv6 => String::from("icmpv6"),
            IpNextLevelProtocol::Tcp => String::from("tcp"),
            IpNextLevelProtocol::Udp => String::from("udp"),
            IpNextLevelProtocol::Unknown(n) => format!("unknown_{}", n),
        }
    }
    pub fn name(&self) -> String {
        match *self {
            IpNextLevelProtocol::Icmp => String::from("ICMP"),
            IpNextLevelProtocol::Icmpv6 => String::from("ICMPv6"),
            IpNextLevelProtocol::Tcp => String::from("TCP"),
            IpNextLevelProtocol::Udp => String::from("UDP"),
            IpNextLevelProtocol::Unknown(n) => format!("Unknown({})", n),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct IpFingerprint {
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub version: u8,
    pub ttl: u8,
    pub tos: u8,
    pub id: u16,
    pub df: bool,
    pub flags: u8,
    pub fragment_offset: u16,
    pub header_length: u8,
    pub total_length: u16,
    pub next_level_protocol: IpNextLevelProtocol,
}
