use crate::datalink::MacAddr;
use pnet::packet::Packet;

/// Represents the Ethernet header length.
pub const ETHERNET_HEADER_LEN: usize = 14;

/// Represents the Ethernet types.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum EtherType {
    Ipv4,
    Arp,
    WakeOnLan,
    Trill,
    DECnet,
    Rarp,
    AppleTalk,
    Aarp,
    Ipx,
    Qnx,
    Ipv6,
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
    /// Constructs a new EtherType from u16
    pub fn from_u16(n: u16) -> Option<EtherType> {
        match n {
            0x0800 => Some(EtherType::Ipv4),
            0x0806 => Some(EtherType::Arp),
            0x0842 => Some(EtherType::WakeOnLan),
            0x22F3 => Some(EtherType::Trill),
            0x6003 => Some(EtherType::DECnet),
            0x8035 => Some(EtherType::Rarp),
            0x809B => Some(EtherType::AppleTalk),
            0x80F3 => Some(EtherType::Aarp),
            0x8137 => Some(EtherType::Ipx),
            0x8204 => Some(EtherType::Qnx),
            0x86DD => Some(EtherType::Ipv6),
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
    /// Return the number of the EtherType
    pub fn number(&self) -> u16 {
        match *self {
            EtherType::Ipv4 => 0x0800,
            EtherType::Arp => 0x0806,
            EtherType::WakeOnLan => 0x0842,
            EtherType::Trill => 0x22F3,
            EtherType::DECnet => 0x6003,
            EtherType::Rarp => 0x8035,
            EtherType::AppleTalk => 0x809B,
            EtherType::Aarp => 0x80F3,
            EtherType::Ipx => 0x8137,
            EtherType::Qnx => 0x8204,
            EtherType::Ipv6 => 0x86DD,
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
    /// Return the name of the EtherType
    pub fn name(&self) -> &str {
        match *self {
            EtherType::Ipv4 => "IPv4",
            EtherType::Arp => "ARP",
            EtherType::WakeOnLan => "WakeOnLan",
            EtherType::Trill => "Trill",
            EtherType::DECnet => "DECnet",
            EtherType::Rarp => "RARP",
            EtherType::AppleTalk => "AppleTalk",
            EtherType::Aarp => "AARP",
            EtherType::Ipx => "IPX",
            EtherType::Qnx => "QNX",
            EtherType::Ipv6 => "IPv6",
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

/// Represents an Ethernet packet.
#[derive(Clone, Debug)]
pub struct EthernetPacket {
    /// Destination MAC address
    pub destination: MacAddr,
    /// Source MAC address
    pub source: MacAddr,
    /// EtherType
    pub ethertype: EtherType,
    /// Payload. Next level protocol packet.
    pub payload: Vec<u8>,
}

impl EthernetPacket {
    /// Constructs a new EthernetPacket from pnet::packet::ethernet::EthernetPacket.
    pub(crate) fn from_pnet_packet(
        packet: &pnet::packet::ethernet::EthernetPacket,
    ) -> EthernetPacket {
        EthernetPacket {
            destination: MacAddr::new(packet.get_destination().octets()),
            source: MacAddr::new(packet.get_source().octets()),
            ethertype: EtherType::from_u16(packet.get_ethertype().0).unwrap(),
            payload: packet.payload().to_vec(),
        }
    }
    /// Constructs a new EthernetPacket from bytes
    pub fn from_bytes(packet: &[u8]) -> EthernetPacket {
        let ethernet_packet = pnet::packet::ethernet::EthernetPacket::new(packet).unwrap();
        EthernetPacket::from_pnet_packet(&ethernet_packet)
    }
}

/// Build Ethernet packet
pub(crate) fn build_ethernet_packet(
    eth_packet: &mut pnet::packet::ethernet::MutableEthernetPacket,
    src_mac: MacAddr,
    dst_mac: MacAddr,
    ether_type: EtherType,
) {
    eth_packet.set_source(pnet::datalink::MacAddr::from(src_mac.octets()));
    eth_packet.set_destination(pnet::datalink::MacAddr::from(dst_mac.octets()));
    match ether_type {
        EtherType::Arp => {
            eth_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Arp);
        }
        EtherType::Ipv4 => {
            eth_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv4);
        }
        EtherType::Ipv6 => {
            eth_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv6);
        }
        _ => {
            // TODO
        }
    }
}

/// Build Ethernet ARP packet
pub(crate) fn build_ethernet_arp_packet(
    eth_packet: &mut pnet::packet::ethernet::MutableEthernetPacket,
    src_mac: MacAddr,
) {
    eth_packet.set_source(pnet::datalink::MacAddr::from(src_mac.octets()));
    eth_packet.set_destination(pnet::datalink::MacAddr::broadcast());
    eth_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Arp);
}

/// Ethernet Packet Builder
#[derive(Clone, Debug)]
pub struct EthernetPacketBuilder {
    /// Source MAC address
    pub src_mac: MacAddr,
    /// Destination MAC address
    pub dst_mac: MacAddr,
    /// EtherType
    pub ether_type: EtherType,
}

impl EthernetPacketBuilder {
    /// Constructs a new EthernetPacketBuilder
    pub fn new() -> EthernetPacketBuilder {
        EthernetPacketBuilder {
            src_mac: MacAddr::new([0; 6]),
            dst_mac: MacAddr::new([0; 6]),
            ether_type: EtherType::Ipv4,
        }
    }
    /// Build Ethernet packet and return bytes
    pub fn build(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![0; ETHERNET_HEADER_LEN];
        let mut eth_packet =
            pnet::packet::ethernet::MutableEthernetPacket::new(&mut buffer).unwrap();
        build_ethernet_packet(
            &mut eth_packet,
            self.src_mac.clone(),
            self.dst_mac.clone(),
            self.ether_type,
        );
        eth_packet.to_immutable().packet().to_vec()
    }
}

/// Create Dummy Ethernet Frame
pub(crate) fn create_dummy_ethernet_frame(
    payload_offset: usize,
    packet: &[u8],
) -> Vec<u8> {
    if packet.len() <= payload_offset {
        return packet.to_vec();
    }
    let mut buffer: Vec<u8> = vec![0; ETHERNET_HEADER_LEN];
    let src_mac: MacAddr = MacAddr::zero();
    let dst_mac: MacAddr = MacAddr::zero();
    let mut ether_type: EtherType = EtherType::Unknown(0);
    let mut eth_packet = pnet::packet::ethernet::MutableEthernetPacket::new(&mut buffer).unwrap();
    if let Some (ip_packet) = pnet::packet::ipv4::Ipv4Packet::new(&packet[payload_offset..]) {
        let version = ip_packet.get_version();
        if version == 4 {
            ether_type = EtherType::Ipv4;
        }
        else if version == 6 {
            ether_type = EtherType::Ipv6;
        }
    }
    build_ethernet_packet(&mut eth_packet, src_mac, dst_mac, ether_type);
    eth_packet.set_payload(&packet[payload_offset..]);
    eth_packet.to_immutable().packet().to_vec()
}
