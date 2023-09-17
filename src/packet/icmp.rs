use pnet::packet::Packet;

pub const ICMPV4_HEADER_LEN: usize =
    pnet::packet::icmp::echo_request::MutableEchoRequestPacket::minimum_packet_size();

/// ICMP types
/// <https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml>
#[derive(Clone, Debug, PartialEq)]
pub enum IcmpType {
    EchoReply,
    DestinationUnreachable,
    SourceQuench,
    RedirectMessage,
    EchoRequest,
    RouterAdvertisement,
    RouterSolicitation,
    TimeExceeded,
    ParameterProblem,
    TimestampRequest,
    TimestampReply,
    InformationRequest,
    InformationReply,
    AddressMaskRequest,
    AddressMaskReply,
    Traceroute,
    DatagramConversionError,
    MobileHostRedirect,
    IPv6WhereAreYou,
    IPv6IAmHere,
    MobileRegistrationRequest,
    MobileRegistrationReply,
    DomainNameRequest,
    DomainNameReply,
    SKIP,
    Photuris,
    Unknown(u8),
}

impl IcmpType {
    /// Get the number of the ICMP type
    pub fn number(&self) -> u8 {
        match *self {
            IcmpType::EchoReply => 0,
            IcmpType::DestinationUnreachable => 3,
            IcmpType::SourceQuench => 4,
            IcmpType::RedirectMessage => 5,
            IcmpType::EchoRequest => 8,
            IcmpType::RouterAdvertisement => 9,
            IcmpType::RouterSolicitation => 10,
            IcmpType::TimeExceeded => 11,
            IcmpType::ParameterProblem => 12,
            IcmpType::TimestampRequest => 13,
            IcmpType::TimestampReply => 14,
            IcmpType::InformationRequest => 15,
            IcmpType::InformationReply => 16,
            IcmpType::AddressMaskRequest => 17,
            IcmpType::AddressMaskReply => 18,
            IcmpType::Traceroute => 30,
            IcmpType::DatagramConversionError => 31,
            IcmpType::MobileHostRedirect => 32,
            IcmpType::IPv6WhereAreYou => 33,
            IcmpType::IPv6IAmHere => 34,
            IcmpType::MobileRegistrationRequest => 35,
            IcmpType::MobileRegistrationReply => 36,
            IcmpType::DomainNameRequest => 37,
            IcmpType::DomainNameReply => 38,
            IcmpType::SKIP => 39,
            IcmpType::Photuris => 40,
            IcmpType::Unknown(n) => n,
        }
    }
    /// Get the ID of the ICMP type
    pub fn id(&self) -> String {
        match *self {
            IcmpType::EchoReply => String::from("echo_reply"),
            IcmpType::DestinationUnreachable => String::from("destination_unreachable"),
            IcmpType::SourceQuench => String::from("source_quench"),
            IcmpType::RedirectMessage => String::from("redirect_message"),
            IcmpType::EchoRequest => String::from("echo_request"),
            IcmpType::RouterAdvertisement => String::from("router_advertisement"),
            IcmpType::RouterSolicitation => String::from("router_solicitation"),
            IcmpType::TimeExceeded => String::from("time_exceeded"),
            IcmpType::ParameterProblem => String::from("parameter_problem"),
            IcmpType::TimestampRequest => String::from("timestamp_request"),
            IcmpType::TimestampReply => String::from("timestamp_reply"),
            IcmpType::InformationRequest => String::from("information_request"),
            IcmpType::InformationReply => String::from("information_reply"),
            IcmpType::AddressMaskRequest => String::from("address_mask_request"),
            IcmpType::AddressMaskReply => String::from("address_mask_reply"),
            IcmpType::Traceroute => String::from("traceroute"),
            IcmpType::DatagramConversionError => String::from("datagram_conversion_error"),
            IcmpType::MobileHostRedirect => String::from("mobile_host_redirect"),
            IcmpType::IPv6WhereAreYou => String::from("ipv6_where_are_you"),
            IcmpType::IPv6IAmHere => String::from("ipv6_i_am_here"),
            IcmpType::MobileRegistrationRequest => String::from("mobile_registration_request"),
            IcmpType::MobileRegistrationReply => String::from("mobile_registration_reply"),
            IcmpType::DomainNameRequest => String::from("domain_name_request"),
            IcmpType::DomainNameReply => String::from("domain_name_reply"),
            IcmpType::SKIP => String::from("skip"),
            IcmpType::Photuris => String::from("photuris"),
            IcmpType::Unknown(n) => format!("unknown_{}", n),
        }
    }
    /// Get the name of the ICMP type
    pub fn name(&self) -> String {
        match *self {
            IcmpType::EchoReply => String::from("Echo Reply"),
            IcmpType::DestinationUnreachable => String::from("Destination Unreachable"),
            IcmpType::SourceQuench => String::from("Source Quench"),
            IcmpType::RedirectMessage => String::from("Redirect Message"),
            IcmpType::EchoRequest => String::from("Echo Request"),
            IcmpType::RouterAdvertisement => String::from("Router Advertisement"),
            IcmpType::RouterSolicitation => String::from("Router Solicitation"),
            IcmpType::TimeExceeded => String::from("Time Exceeded"),
            IcmpType::ParameterProblem => String::from("Parameter Problem"),
            IcmpType::TimestampRequest => String::from("Timestamp Request"),
            IcmpType::TimestampReply => String::from("Timestamp Reply"),
            IcmpType::InformationRequest => String::from("Information Request"),
            IcmpType::InformationReply => String::from("Information Reply"),
            IcmpType::AddressMaskRequest => String::from("Address Mask Request"),
            IcmpType::AddressMaskReply => String::from("Address Mask Reply"),
            IcmpType::Traceroute => String::from("Traceroute"),
            IcmpType::DatagramConversionError => String::from("Datagram Conversion Error"),
            IcmpType::MobileHostRedirect => String::from("Mobile Host Redirect"),
            IcmpType::IPv6WhereAreYou => String::from("IPv6 Where Are You"),
            IcmpType::IPv6IAmHere => String::from("IPv6 I Am Here"),
            IcmpType::MobileRegistrationRequest => String::from("Mobile Registration Request"),
            IcmpType::MobileRegistrationReply => String::from("Mobile Registration Reply"),
            IcmpType::DomainNameRequest => String::from("Domain Name Request"),
            IcmpType::DomainNameReply => String::from("Domain Name Reply"),
            IcmpType::SKIP => String::from("SKIP"),
            IcmpType::Photuris => String::from("Photuris"),
            IcmpType::Unknown(n) => format!("Unknown ({})", n),
        }
    }
    pub(crate) fn from_pnet_type(t: pnet::packet::icmp::IcmpType) -> IcmpType {
        match t {
            pnet::packet::icmp::IcmpTypes::EchoReply => IcmpType::EchoReply,
            pnet::packet::icmp::IcmpTypes::DestinationUnreachable => IcmpType::DestinationUnreachable,
            pnet::packet::icmp::IcmpTypes::SourceQuench => IcmpType::SourceQuench,
            pnet::packet::icmp::IcmpTypes::RedirectMessage => IcmpType::RedirectMessage,
            pnet::packet::icmp::IcmpTypes::EchoRequest => IcmpType::EchoRequest,
            pnet::packet::icmp::IcmpTypes::RouterAdvertisement => IcmpType::RouterAdvertisement,
            pnet::packet::icmp::IcmpTypes::RouterSolicitation => IcmpType::RouterSolicitation,
            pnet::packet::icmp::IcmpTypes::TimeExceeded => IcmpType::TimeExceeded,
            pnet::packet::icmp::IcmpTypes::ParameterProblem => IcmpType::ParameterProblem,
            pnet::packet::icmp::IcmpTypes::Timestamp => IcmpType::TimestampRequest,
            pnet::packet::icmp::IcmpTypes::TimestampReply => IcmpType::TimestampReply,
            pnet::packet::icmp::IcmpTypes::InformationRequest => IcmpType::InformationRequest,
            pnet::packet::icmp::IcmpTypes::InformationReply => IcmpType::InformationReply,
            pnet::packet::icmp::IcmpTypes::AddressMaskRequest => IcmpType::AddressMaskRequest,
            pnet::packet::icmp::IcmpTypes::AddressMaskReply => IcmpType::AddressMaskReply,
            pnet::packet::icmp::IcmpTypes::Traceroute => IcmpType::Traceroute,
            _ => IcmpType::Unknown(t.0),
        }
    }
}

/// Represents the "ICMP code" header field.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IcmpCode {
    NetworkUnreachable,
    HostUnreachable,
    ProtocolUnreachable,
    PortUnreachable,
    FragmentationNeeded,
    SourceRouteFailed,
    DestinationNetworkUnknown,
    DestinationHostUnknown,
    SourceHostIsolated,
    NetworkAdministrativelyProhibited,
    HostAdministrativelyProhibited,
    NetworkUnreachableForTos,
    HostUnreachableForTos,
    CommunicationAdministrativelyProhibited,
    HostPrecedenceViolation,
    PrecedenceCutoffInEffect,
    Unknown(u8),
}

impl IcmpCode {
    pub fn from_u8(n: u8) ->IcmpCode {
        match n {
            0 => IcmpCode::NetworkUnreachable,
            1 => IcmpCode::HostUnreachable,
            2 => IcmpCode::ProtocolUnreachable,
            3 => IcmpCode::PortUnreachable,
            4 => IcmpCode::FragmentationNeeded,
            5 => IcmpCode::SourceRouteFailed,
            6 => IcmpCode::DestinationNetworkUnknown,
            7 => IcmpCode::DestinationHostUnknown,
            8 => IcmpCode::SourceHostIsolated,
            9 => IcmpCode::NetworkAdministrativelyProhibited,
            10 => IcmpCode::HostAdministrativelyProhibited,
            11 => IcmpCode::NetworkUnreachableForTos,
            12 => IcmpCode::HostUnreachableForTos,
            13 => IcmpCode::CommunicationAdministrativelyProhibited,
            14 => IcmpCode::HostPrecedenceViolation,
            15 => IcmpCode::PrecedenceCutoffInEffect,
            _ => IcmpCode::Unknown(n),
        }
    }
    pub fn number(&self) -> u8 {
        match *self {
            IcmpCode::NetworkUnreachable => 0,
            IcmpCode::HostUnreachable => 1,
            IcmpCode::ProtocolUnreachable => 2,
            IcmpCode::PortUnreachable => 3,
            IcmpCode::FragmentationNeeded => 4,
            IcmpCode::SourceRouteFailed => 5,
            IcmpCode::DestinationNetworkUnknown => 6,
            IcmpCode::DestinationHostUnknown => 7,
            IcmpCode::SourceHostIsolated => 8,
            IcmpCode::NetworkAdministrativelyProhibited => 9,
            IcmpCode::HostAdministrativelyProhibited => 10,
            IcmpCode::NetworkUnreachableForTos => 11,
            IcmpCode::HostUnreachableForTos => 12,
            IcmpCode::CommunicationAdministrativelyProhibited => 13,
            IcmpCode::HostPrecedenceViolation => 14,
            IcmpCode::PrecedenceCutoffInEffect => 15,
            IcmpCode::Unknown(n) => n,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct IcmpPacket {
    pub icmp_type: IcmpType,
    pub icmp_code: IcmpCode,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

impl IcmpPacket {
    pub(crate) fn from_pnet_packet(packet: &pnet::packet::icmp::IcmpPacket) -> IcmpPacket {
        IcmpPacket {
            icmp_type: IcmpType::from_pnet_type(packet.get_icmp_type()),
            icmp_code: IcmpCode::from_u8(packet.get_icmp_code().0),
            checksum: packet.get_checksum(),
            payload: packet.payload().to_vec(),
        }
    }
    pub fn from_bytes(packet: &[u8]) -> IcmpPacket {
        let icmp_packet = pnet::packet::icmp::IcmpPacket::new(packet).unwrap();
        IcmpPacket::from_pnet_packet(&icmp_packet)
    }
}

pub fn build_icmp_echo_packet(icmp_packet: &mut pnet::packet::icmp::echo_request::MutableEchoRequestPacket) {
    icmp_packet.set_icmp_type(pnet::packet::icmp::IcmpTypes::EchoRequest);
    icmp_packet.set_sequence_number(rand::random::<u16>());
    icmp_packet.set_identifier(rand::random::<u16>());
    let icmp_check_sum = pnet::packet::util::checksum(&icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmp_check_sum);
}
