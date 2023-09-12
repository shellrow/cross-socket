#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum EtherType {
    IPv4,
    IPv6,
    Unknown(u16),
}

impl EtherType {
    pub fn number(&self) -> u16 {
        match *self {
            EtherType::IPv4 => 0x0800,
            EtherType::IPv6 => 0x86DD,
            EtherType::Unknown(n) => n,
        }
    }
    pub fn id(&self) -> String {
        match *self {
            EtherType::IPv4 => String::from("ipv4"),
            EtherType::IPv6 => String::from("ipv6"),
            EtherType::Unknown(n) => format!("unknown_{}", n),
        }
    }
    pub fn name(&self) -> String {
        match *self {
            EtherType::IPv4 => String::from("IPv4"),
            EtherType::IPv6 => String::from("IPv6"),
            EtherType::Unknown(n) => format!("Unknown({})", n),
        }
    }
}
