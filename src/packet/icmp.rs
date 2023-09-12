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

/// ICMPv6 types
/// <https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml>
#[derive(Clone, Debug, PartialEq)]
pub enum Icmpv6Type {
    DestinationUnreachable,
    PacketTooBig,
    TimeExceeded,
    ParameterProblem,
    EchoRequest,
    EchoReply,
    MulticastListenerQuery,
    MulticastListenerReport,
    MulticastListenerDone,
    RouterSolicitation,
    RouterAdvertisement,
    NeighborSolicitation,
    NeighborAdvertisement,
    RedirectMessage,
    RouterRenumbering,
    NodeInformationQuery,
    NodeInformationResponse,
    InverseNeighborDiscoverySolicitation,
    InverseNeighborDiscoveryAdvertisement,
    Version2MulticastListenerReport,
    HomeAgentAddressDiscoveryRequest,
    HomeAgentAddressDiscoveryReply,
    MobilePrefixSolicitation,
    MobilePrefixAdvertisement,
    CertificationPathSolicitationMessage,
    CertificationPathAdvertisementMessage,
    ExperimentalMobilityProtocols,
    MulticastRouterAdvertisement,
    MulticastRouterSolicitation,
    MulticastRouterTermination,
    FMIPv6Messages,
    RPLControlMessage,
    ILNPv6LocatorUpdateMessage,
    DuplicateAddressRequest,
    DuplicateAddressConfirmation,
    MPLControlMessage,
    ExtendedEchoRequest,
    ExtendedEchoReply,
    Unknown(u8),
}

impl Icmpv6Type {
    /// Get the number of the ICMPv6 type
    pub fn number(&self) -> u8 {
        match *self {
            Icmpv6Type::DestinationUnreachable => 1,
            Icmpv6Type::PacketTooBig => 2,
            Icmpv6Type::TimeExceeded => 3,
            Icmpv6Type::ParameterProblem => 4,
            Icmpv6Type::EchoRequest => 128,
            Icmpv6Type::EchoReply => 129,
            Icmpv6Type::MulticastListenerQuery => 130,
            Icmpv6Type::MulticastListenerReport => 131,
            Icmpv6Type::MulticastListenerDone => 132,
            Icmpv6Type::RouterSolicitation => 133,
            Icmpv6Type::RouterAdvertisement => 134,
            Icmpv6Type::NeighborSolicitation => 135,
            Icmpv6Type::NeighborAdvertisement => 136,
            Icmpv6Type::RedirectMessage => 137,
            Icmpv6Type::RouterRenumbering => 138,
            Icmpv6Type::NodeInformationQuery => 139,
            Icmpv6Type::NodeInformationResponse => 140,
            Icmpv6Type::InverseNeighborDiscoverySolicitation => 141,
            Icmpv6Type::InverseNeighborDiscoveryAdvertisement => 142,
            Icmpv6Type::Version2MulticastListenerReport => 143,
            Icmpv6Type::HomeAgentAddressDiscoveryRequest => 144,
            Icmpv6Type::HomeAgentAddressDiscoveryReply => 145,
            Icmpv6Type::MobilePrefixSolicitation => 146,
            Icmpv6Type::MobilePrefixAdvertisement => 147,
            Icmpv6Type::CertificationPathSolicitationMessage => 148,
            Icmpv6Type::CertificationPathAdvertisementMessage => 149,
            Icmpv6Type::ExperimentalMobilityProtocols => 150,
            Icmpv6Type::MulticastRouterAdvertisement => 151,
            Icmpv6Type::MulticastRouterSolicitation => 152,
            Icmpv6Type::MulticastRouterTermination => 153,
            Icmpv6Type::FMIPv6Messages => 154,
            Icmpv6Type::RPLControlMessage => 155,
            Icmpv6Type::ILNPv6LocatorUpdateMessage => 156,
            Icmpv6Type::DuplicateAddressRequest => 157,
            Icmpv6Type::DuplicateAddressConfirmation => 158,
            Icmpv6Type::MPLControlMessage => 159,
            Icmpv6Type::ExtendedEchoRequest => 160,
            Icmpv6Type::ExtendedEchoReply => 161,
            Icmpv6Type::Unknown(n) => n,
        }
    }
    /// Get the id of the ICMPv6 type
    pub fn id(&self) -> String {
        match *self {
            Icmpv6Type::DestinationUnreachable => String::from("destination_unreachable"),
            Icmpv6Type::PacketTooBig => String::from("packet_too_big"),
            Icmpv6Type::TimeExceeded => String::from("time_exceeded"),
            Icmpv6Type::ParameterProblem => String::from("parameter_problem"),
            Icmpv6Type::EchoRequest => String::from("echo_request"),
            Icmpv6Type::EchoReply => String::from("echo_reply"),
            Icmpv6Type::MulticastListenerQuery => String::from("multicast_listener_query"),
            Icmpv6Type::MulticastListenerReport => String::from("multicast_listener_report"),
            Icmpv6Type::MulticastListenerDone => String::from("multicast_listener_done"),
            Icmpv6Type::RouterSolicitation => String::from("router_solicitation"),
            Icmpv6Type::RouterAdvertisement => String::from("router_advertisement"),
            Icmpv6Type::NeighborSolicitation => String::from("neighbor_solicitation"),
            Icmpv6Type::NeighborAdvertisement => String::from("neighbor_advertisement"),
            Icmpv6Type::RedirectMessage => String::from("redirect_message"),
            Icmpv6Type::RouterRenumbering => String::from("router_renumbering"),
            Icmpv6Type::NodeInformationQuery => String::from("node_information_query"),
            Icmpv6Type::NodeInformationResponse => String::from("node_information_response"),
            Icmpv6Type::InverseNeighborDiscoverySolicitation => {
                String::from("inverse_neighbor_discovery_solicitation")
            }
            Icmpv6Type::InverseNeighborDiscoveryAdvertisement => {
                String::from("inverse_neighbor_discovery_advertisement")
            }
            Icmpv6Type::Version2MulticastListenerReport => {
                String::from("version_2_multicast_listener_report")
            }
            Icmpv6Type::HomeAgentAddressDiscoveryRequest => {
                String::from("home_agent_address_discovery_request")
            }
            Icmpv6Type::HomeAgentAddressDiscoveryReply => {
                String::from("home_agent_address_discovery_reply")
            }
            Icmpv6Type::MobilePrefixSolicitation => String::from("mobile_prefix_solicitation"),
            Icmpv6Type::MobilePrefixAdvertisement => String::from("mobile_prefix_advertisement"),
            Icmpv6Type::CertificationPathSolicitationMessage => {
                String::from("certification_path_solicitation_message")
            }
            Icmpv6Type::CertificationPathAdvertisementMessage => {
                String::from("certification_path_advertisement_message")
            }
            Icmpv6Type::ExperimentalMobilityProtocols => {
                String::from("experimental_mobility_protocols")
            }
            Icmpv6Type::MulticastRouterAdvertisement => {
                String::from("multicast_router_advertisement")
            }
            Icmpv6Type::MulticastRouterSolicitation => {
                String::from("multicast_router_solicitation")
            }
            Icmpv6Type::MulticastRouterTermination => {
                String::from("multicast_router_termination")
            }
            Icmpv6Type::FMIPv6Messages => String::from("fmipv6_messages"),
            Icmpv6Type::RPLControlMessage => String::from("rpl_control_message"),
            Icmpv6Type::ILNPv6LocatorUpdateMessage => {
                String::from("ilnpv6_locator_update_message")
            }
            Icmpv6Type::DuplicateAddressRequest => String::from("duplicate_address_request"),
            Icmpv6Type::DuplicateAddressConfirmation => {
                String::from("duplicate_address_confirmation")
            }
            Icmpv6Type::MPLControlMessage => String::from("mpl_control_message"),
            Icmpv6Type::ExtendedEchoRequest => String::from("extended_echo_request"),
            Icmpv6Type::ExtendedEchoReply => String::from("extended_echo_reply"),
            Icmpv6Type::Unknown(n) => format!("unknown_{}", n),
        }
    }
    /// Get the name of the ICMPv6 type
    pub fn name(&self) -> String {
        match *self {
            Icmpv6Type::DestinationUnreachable => String::from("Destination Unreachable"),
            Icmpv6Type::PacketTooBig => String::from("Packet Too Big"),
            Icmpv6Type::TimeExceeded => String::from("Time Exceeded"),
            Icmpv6Type::ParameterProblem => String::from("Parameter Problem"),
            Icmpv6Type::EchoRequest => String::from("Echo Request"),
            Icmpv6Type::EchoReply => String::from("Echo Reply"),
            Icmpv6Type::MulticastListenerQuery => String::from("Multicast Listener Query"),
            Icmpv6Type::MulticastListenerReport => String::from("Multicast Listener Report"),
            Icmpv6Type::MulticastListenerDone => String::from("Multicast Listener Done"),
            Icmpv6Type::RouterSolicitation => String::from("Router Solicitation"),
            Icmpv6Type::RouterAdvertisement => String::from("Router Advertisement"),
            Icmpv6Type::NeighborSolicitation => String::from("Neighbor Solicitation"),
            Icmpv6Type::NeighborAdvertisement => String::from("Neighbor Advertisement"),
            Icmpv6Type::RedirectMessage => String::from("Redirect Message"),
            Icmpv6Type::RouterRenumbering => String::from("Router Renumbering"),
            Icmpv6Type::NodeInformationQuery => String::from("Node Information Query"),
            Icmpv6Type::NodeInformationResponse => String::from("Node Information Response"),
            Icmpv6Type::InverseNeighborDiscoverySolicitation => {
                String::from("Inverse Neighbor Discovery Solicitation")
            }
            Icmpv6Type::InverseNeighborDiscoveryAdvertisement => {
                String::from("Inverse Neighbor Discovery Advertisement")
            }
            Icmpv6Type::Version2MulticastListenerReport => {
                String::from("Version 2 Multicast Listener Report")
            }
            Icmpv6Type::HomeAgentAddressDiscoveryRequest => {
                String::from("Home Agent Address Discovery Request")
            }
            Icmpv6Type::HomeAgentAddressDiscoveryReply => {
                String::from("Home Agent Address Discovery Reply")
            }
            Icmpv6Type::MobilePrefixSolicitation => String::from("Mobile Prefix Solicitation"),
            Icmpv6Type::MobilePrefixAdvertisement => String::from("Mobile Prefix Advertisement"),
            Icmpv6Type::CertificationPathSolicitationMessage => {
                String::from("Certification Path Solicitation Message")
            }
            Icmpv6Type::CertificationPathAdvertisementMessage => {
                String::from("Certification Path Advertisement Message")
            }
            Icmpv6Type::ExperimentalMobilityProtocols => {
                String::from("Experimental Mobility Protocols")
            }
            Icmpv6Type::MulticastRouterAdvertisement => {
                String::from("Multicast Router Advertisement")
            }
            Icmpv6Type::MulticastRouterSolicitation => {
                String::from("Multicast Router Solicitation")
            }
            Icmpv6Type::MulticastRouterTermination => {
                String::from("Multicast Router Termination")
            }
            Icmpv6Type::FMIPv6Messages => String::from("FMIPv6 Messages"),
            Icmpv6Type::RPLControlMessage => String::from("RPL Control Message"),
            Icmpv6Type::ILNPv6LocatorUpdateMessage => String::from("ILNPv6 Locator Update Message"),
            Icmpv6Type::DuplicateAddressRequest => String::from("Duplicate Address Request"),
            Icmpv6Type::DuplicateAddressConfirmation => {
                String::from("Duplicate Address Confirmation")
            }
            Icmpv6Type::MPLControlMessage => String::from("MPL Control Message"),
            Icmpv6Type::ExtendedEchoRequest => String::from("Extended Echo Request"),
            Icmpv6Type::ExtendedEchoReply => String::from("Extended Echo Reply"),
            Icmpv6Type::Unknown(n) => format!("Unknown ({})", n),
        }
    }
    pub(crate) fn from_pnet_type(t: pnet::packet::icmpv6::Icmpv6Type) -> Icmpv6Type {
        match t {
            pnet::packet::icmpv6::Icmpv6Types::DestinationUnreachable => {
                Icmpv6Type::DestinationUnreachable
            }
            pnet::packet::icmpv6::Icmpv6Types::PacketTooBig => Icmpv6Type::PacketTooBig,
            pnet::packet::icmpv6::Icmpv6Types::TimeExceeded => Icmpv6Type::TimeExceeded,
            pnet::packet::icmpv6::Icmpv6Types::ParameterProblem => Icmpv6Type::ParameterProblem,
            pnet::packet::icmpv6::Icmpv6Types::EchoRequest => Icmpv6Type::EchoRequest,
            pnet::packet::icmpv6::Icmpv6Types::EchoReply => Icmpv6Type::EchoReply,
            _ => Icmpv6Type::Unknown(t.0),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct IcmpFingerprint {
    pub icmp_type: IcmpType,
    pub icmp_code: u8,
    pub payload_length: u16,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Icmpv6Fingerprint {
    pub icmpv6_type: Icmpv6Type,
    pub icmpv6_code: u8,
    pub payload_length: u16,
    pub payload: Vec<u8>,
}
