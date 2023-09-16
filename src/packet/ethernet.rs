use pnet::packet::Packet;
use crate::datalink::MacAddr;

// define the EtherType enum from avove as a const
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum EtherType {
    IPv4,
    Arp,
    WakeOnLan,
    Trill,
    DECnet,
    Rarp,
    AppleTalk,
    Aarp,
    Ipx,
    Qnx,
    IPv6,
    FlowControl,
    CobraNet,
    Mpls,
    MplsMcast,
    PppoeDiscovery,
    PppoeSession,
    Vlan,
    PBridge,
    Lldp,
    Ptp,
    Cfm,
    QinQ,
    Unknown(u16),
}

impl EtherType {
    pub fn from_u16(n: u16) -> Option<EtherType> {
        match n {
            0x0800 => Some(EtherType::IPv4),
            0x0806 => Some(EtherType::Arp),
            0x0842 => Some(EtherType::WakeOnLan),
            0x22F3 => Some(EtherType::Trill),
            0x6003 => Some(EtherType::DECnet),
            0x8035 => Some(EtherType::Rarp),
            0x809B => Some(EtherType::AppleTalk),
            0x80F3 => Some(EtherType::Aarp),
            0x8137 => Some(EtherType::Ipx),
            0x8204 => Some(EtherType::Qnx),
            0x86DD => Some(EtherType::IPv6),
            0x8808 => Some(EtherType::FlowControl),
            0x8819 => Some(EtherType::CobraNet),
            0x8847 => Some(EtherType::Mpls),
            0x8848 => Some(EtherType::MplsMcast),
            0x8863 => Some(EtherType::PppoeDiscovery),
            0x8864 => Some(EtherType::PppoeSession),
            0x8100 => Some(EtherType::Vlan),
            0x88a8 => Some(EtherType::PBridge),
            0x88cc => Some(EtherType::Lldp),
            0x88f7 => Some(EtherType::Ptp),
            0x8902 => Some(EtherType::Cfm),
            0x9100 => Some(EtherType::QinQ),
            _ => Some(EtherType::Unknown(n)),
        }
    }
    pub fn number(&self) -> u16 {
        match *self {
            EtherType::IPv4 => 0x0800,
            EtherType::Arp => 0x0806,
            EtherType::WakeOnLan => 0x0842,
            EtherType::Trill => 0x22F3,
            EtherType::DECnet => 0x6003,
            EtherType::Rarp => 0x8035,
            EtherType::AppleTalk => 0x809B,
            EtherType::Aarp => 0x80F3,
            EtherType::Ipx => 0x8137,
            EtherType::Qnx => 0x8204,
            EtherType::IPv6 => 0x86DD,
            EtherType::FlowControl => 0x8808,
            EtherType::CobraNet => 0x8819,
            EtherType::Mpls => 0x8847,
            EtherType::MplsMcast => 0x8848,
            EtherType::PppoeDiscovery => 0x8863,
            EtherType::PppoeSession => 0x8864,
            EtherType::Vlan => 0x8100,
            EtherType::PBridge => 0x88a8,
            EtherType::Lldp => 0x88cc,
            EtherType::Ptp => 0x88f7,
            EtherType::Cfm => 0x8902,
            EtherType::QinQ => 0x9100,
            EtherType::Unknown(n) => n,
        }
    }
    pub fn name(&self) -> &str {
        match *self {
            EtherType::IPv4 => "IPv4",
            EtherType::Arp => "ARP",
            EtherType::WakeOnLan => "WakeOnLan",
            EtherType::Trill => "Trill",
            EtherType::DECnet => "DECnet",
            EtherType::Rarp => "RARP",
            EtherType::AppleTalk => "AppleTalk",
            EtherType::Aarp => "AARP",
            EtherType::Ipx => "IPX",
            EtherType::Qnx => "QNX",
            EtherType::IPv6 => "IPv6",
            EtherType::FlowControl => "FlowControl",
            EtherType::CobraNet => "CobraNet",
            EtherType::Mpls => "MPLS",
            EtherType::MplsMcast => "MPLS Multicast",
            EtherType::PppoeDiscovery => "PPPoE Discovery",
            EtherType::PppoeSession => "PPPoE Session",
            EtherType::Vlan => "VLAN",
            EtherType::PBridge => "Provider Bridging",
            EtherType::Lldp => "LLDP",
            EtherType::Ptp => "PTP",
            EtherType::Cfm => "CFM",
            EtherType::QinQ => "QinQ",
            EtherType::Unknown(_) => "Unknown",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EthernetPacket {
    pub destination: MacAddr,
    pub source: MacAddr,
    pub ethertype: EtherType,
    pub payload: Vec<u8>,
}

impl EthernetPacket {
    pub(crate) fn from_pnet_packet(packet: &pnet::packet::ethernet::EthernetPacket) -> EthernetPacket {
        EthernetPacket {
            destination: MacAddr::new(packet.get_destination().octets()),
            source: MacAddr::new(packet.get_source().octets()),
            ethertype: EtherType::from_u16(packet.get_ethertype().0).unwrap(),
            payload: packet.payload().to_vec(),
        }
    }
}
