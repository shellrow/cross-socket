use std::net::Ipv4Addr;
use pnet::packet::Packet;
use crate::datalink::MacAddr;
use crate::packet::ethernet::EtherType;

pub const ARP_HEADER_LEN: usize = 28;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArpOperation{
    Request = 1,
    Reply = 2,
    RarpRequest = 3,
    RarpReply = 4,
    InRequest = 8,
    InReply = 9,
    Nak = 10,
}

impl ArpOperation {
    pub fn from_u16(n: u16) -> Option<ArpOperation> {
        match n {
            1 => Some(ArpOperation::Request),
            2 => Some(ArpOperation::Reply),
            3 => Some(ArpOperation::RarpRequest),
            4 => Some(ArpOperation::RarpReply),
            8 => Some(ArpOperation::InRequest),
            9 => Some(ArpOperation::InReply),
            10 => Some(ArpOperation::Nak),
            _ => None,
        }
    }
}

/// Represents the ARP hardware types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArpHardwareType {
    /// Ethernet (10Mb)
    Ethernet = 1,
    /// Experimental Ethernet (3Mb)
    ExperimentalEthernet = 2,
    /// Amateur Radio AX.25
    AmateurRadioAX25 = 3,
    /// Proteon ProNET Token Ring
    ProteonProNETTokenRing = 4,
    /// Chaos
    Chaos = 5,
    /// IEEE 802 Networks
    IEEE802Networks = 6,
    /// ARCNET
    ARCNET = 7,
    /// Hyperchannel
    Hyperchannel = 8,
    /// Lanstar
    Lanstar = 9,
    /// Autonet Short Address
    AutonetShortAddress = 10,
    /// LocalTalk
    LocalTalk = 11,
    /// LocalNet (IBM PCNet or SYTEK LocalNET)
    LocalNet = 12,
    /// Ultra link
    UltraLink = 13,
    /// SMDS
    SMDS = 14,
    /// Frame Relay
    FrameRelay = 15,
    /// Asynchronous Transmission Mode (ATM)
    AsynchronousTransmissionMode = 16,
    /// HDLC
    HDLC = 17,
    /// Fibre Channel
    FibreChannel = 18,
    /// Asynchronous Transmission Mode (ATM)
    AsynchronousTransmissionMode2 = 19,
    /// Serial Line
    SerialLine = 20,
    /// Asynchronous Transmission Mode (ATM)
    AsynchronousTransmissionMode3 = 21,
    /// MIL-STD-188-220
    MILSTD188220 = 22,
    /// Metricom
    Metricom = 23,
    /// IEEE 1394.1995
    IEEE13941995 = 24,
    /// MAPOS
    MAPOS = 25,
    /// Twinaxial
    Twinaxial = 26,
    /// EUI-64
    EUI64 = 27,
    /// HIPARP
    HIPARP = 28,
    /// IP and ARP over ISO 7816-3
    IPandARPoverISO78163 = 29,
    /// ARPSec
    ARPSec = 30,
    /// IPsec tunnel
    IPsecTunnel = 31,
    /// InfiniBand (TM)
    InfiniBand = 32,
    /// TIA-102 Project 25 Common Air Interface
    TIA102Project25CommonAirInterface = 16384,
    /// Wiegand Interface
    WiegandInterface = 16385,
    /// Pure IP
    PureIP = 16386,
    /// HW_EXP1
    HWEXP1 = 65280,
    /// HW_EXP2
    HWEXP2 = 65281,
    /// AEthernet
    AEthernet = 65282,
}

impl ArpHardwareType {
    pub fn from_u16(n: u16) -> Option<ArpHardwareType> {
        match n {
            1 => Some(ArpHardwareType::Ethernet),
            2 => Some(ArpHardwareType::ExperimentalEthernet),
            3 => Some(ArpHardwareType::AmateurRadioAX25),
            4 => Some(ArpHardwareType::ProteonProNETTokenRing),
            5 => Some(ArpHardwareType::Chaos),
            6 => Some(ArpHardwareType::IEEE802Networks),
            7 => Some(ArpHardwareType::ARCNET),
            8 => Some(ArpHardwareType::Hyperchannel),
            9 => Some(ArpHardwareType::Lanstar),
            10 => Some(ArpHardwareType::AutonetShortAddress),
            11 => Some(ArpHardwareType::LocalTalk),
            12 => Some(ArpHardwareType::LocalNet),
            13 => Some(ArpHardwareType::UltraLink),
            14 => Some(ArpHardwareType::SMDS),
            15 => Some(ArpHardwareType::FrameRelay),
            16 => Some(ArpHardwareType::AsynchronousTransmissionMode),
            17 => Some(ArpHardwareType::HDLC),
            18 => Some(ArpHardwareType::FibreChannel),
            19 => Some(ArpHardwareType::AsynchronousTransmissionMode2),
            20 => Some(ArpHardwareType::SerialLine),
            21 => Some(ArpHardwareType::AsynchronousTransmissionMode3),
            22 => Some(ArpHardwareType::MILSTD188220),
            23 => Some(ArpHardwareType::Metricom),
            24 => Some(ArpHardwareType::IEEE13941995),
            25 => Some(ArpHardwareType::MAPOS),
            26 => Some(ArpHardwareType::Twinaxial),
            27 => Some(ArpHardwareType::EUI64),
            28 => Some(ArpHardwareType::HIPARP),
            29 => Some(ArpHardwareType::IPandARPoverISO78163),
            30 => Some(ArpHardwareType::ARPSec),
            31 => Some(ArpHardwareType::IPsecTunnel),
            32 => Some(ArpHardwareType::InfiniBand),
            16384 => Some(ArpHardwareType::TIA102Project25CommonAirInterface),
            16385 => Some(ArpHardwareType::WiegandInterface),
            16386 => Some(ArpHardwareType::PureIP),
            65280 => Some(ArpHardwareType::HWEXP1),
            65281 => Some(ArpHardwareType::HWEXP2),
            65282 => Some(ArpHardwareType::AEthernet),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ArpPacket {
    pub hardware_type: ArpHardwareType,
    pub protocol_type: EtherType,
    pub operation: ArpOperation,
    pub sender_hw_addr: MacAddr,
    pub sender_proto_addr: Ipv4Addr,
    pub target_hw_addr: MacAddr,
    pub target_proto_addr: Ipv4Addr,
    pub payload: Vec<u8>,
}

impl ArpPacket {
    pub(crate) fn from_pnet_packet(packet: pnet::packet::arp::ArpPacket) -> ArpPacket {
        ArpPacket {
            hardware_type: ArpHardwareType::from_u16(packet.get_hardware_type().0).unwrap(),
            protocol_type: EtherType::from_u16(packet.get_protocol_type().0).unwrap(),
            operation: ArpOperation::from_u16(packet.get_operation().0).unwrap(),
            sender_hw_addr: MacAddr::new(packet.get_sender_hw_addr().octets()),
            sender_proto_addr: packet.get_sender_proto_addr(),
            target_hw_addr: MacAddr::new(packet.get_target_hw_addr().octets()),
            target_proto_addr: packet.get_target_proto_addr(),
            payload: packet.payload().to_vec(),
        }
    }
}

pub fn build_arp_packet(
    arp_packet: &mut pnet::packet::arp::MutableArpPacket,
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) {
    arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(pnet::packet::ethernet::EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(pnet::packet::arp::ArpOperations::Request);
    arp_packet.set_sender_hw_addr(pnet::datalink::MacAddr::from(src_mac.octets()));
    arp_packet.set_sender_proto_addr(src_ip);
    arp_packet.set_target_hw_addr(pnet::datalink::MacAddr::from(dst_mac.octets()));
    arp_packet.set_target_proto_addr(dst_ip);
}
