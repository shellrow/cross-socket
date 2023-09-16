use pnet::packet::Packet;

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

/// Represents the "ICMPv6 code" header field.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Icmpv6Code {
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

impl Icmpv6Code {
    pub fn from_u8(t: u8) -> Icmpv6Code {
        match t {
            1 => Icmpv6Code::DestinationUnreachable,
            2 => Icmpv6Code::PacketTooBig,
            3 => Icmpv6Code::TimeExceeded,
            4 => Icmpv6Code::ParameterProblem,
            128 => Icmpv6Code::EchoRequest,
            129 => Icmpv6Code::EchoReply,
            130 => Icmpv6Code::MulticastListenerQuery,
            131 => Icmpv6Code::MulticastListenerReport,
            132 => Icmpv6Code::MulticastListenerDone,
            133 => Icmpv6Code::RouterSolicitation,
            134 => Icmpv6Code::RouterAdvertisement,
            135 => Icmpv6Code::NeighborSolicitation,
            136 => Icmpv6Code::NeighborAdvertisement,
            137 => Icmpv6Code::RedirectMessage,
            138 => Icmpv6Code::RouterRenumbering,
            139 => Icmpv6Code::NodeInformationQuery,
            140 => Icmpv6Code::NodeInformationResponse,
            141 => Icmpv6Code::InverseNeighborDiscoverySolicitation,
            142 => Icmpv6Code::InverseNeighborDiscoveryAdvertisement,
            143 => Icmpv6Code::Version2MulticastListenerReport,
            144 => Icmpv6Code::HomeAgentAddressDiscoveryRequest,
            145 => Icmpv6Code::HomeAgentAddressDiscoveryReply,
            146 => Icmpv6Code::MobilePrefixSolicitation,
            147 => Icmpv6Code::MobilePrefixAdvertisement,
            148 => Icmpv6Code::CertificationPathSolicitationMessage,
            149 => Icmpv6Code::CertificationPathAdvertisementMessage,
            150 => Icmpv6Code::ExperimentalMobilityProtocols,
            151 => Icmpv6Code::MulticastRouterAdvertisement,
            152 => Icmpv6Code::MulticastRouterSolicitation,
            153 => Icmpv6Code::MulticastRouterTermination,
            154 => Icmpv6Code::FMIPv6Messages,
            155 => Icmpv6Code::RPLControlMessage,
            156 => Icmpv6Code::ILNPv6LocatorUpdateMessage,
            157 => Icmpv6Code::DuplicateAddressRequest,
            158 => Icmpv6Code::DuplicateAddressConfirmation,
            159 => Icmpv6Code::MPLControlMessage,
            160 => Icmpv6Code::ExtendedEchoRequest,
            161 => Icmpv6Code::ExtendedEchoReply,
            _ => Icmpv6Code::Unknown(t),
        }
    }
    /// Get the number of the ICMPv6 code
    pub fn number(&self) -> u8 {
        match *self {
            Icmpv6Code::DestinationUnreachable => 1,
            Icmpv6Code::PacketTooBig => 2,
            Icmpv6Code::TimeExceeded => 3,
            Icmpv6Code::ParameterProblem => 4,
            Icmpv6Code::EchoRequest => 128,
            Icmpv6Code::EchoReply => 129,
            Icmpv6Code::MulticastListenerQuery => 130,
            Icmpv6Code::MulticastListenerReport => 131,
            Icmpv6Code::MulticastListenerDone => 132,
            Icmpv6Code::RouterSolicitation => 133,
            Icmpv6Code::RouterAdvertisement => 134,
            Icmpv6Code::NeighborSolicitation => 135,
            Icmpv6Code::NeighborAdvertisement => 136,
            Icmpv6Code::RedirectMessage => 137,
            Icmpv6Code::RouterRenumbering => 138,
            Icmpv6Code::NodeInformationQuery => 139,
            Icmpv6Code::NodeInformationResponse => 140,
            Icmpv6Code::InverseNeighborDiscoverySolicitation => 141,
            Icmpv6Code::InverseNeighborDiscoveryAdvertisement => 142,
            Icmpv6Code::Version2MulticastListenerReport => 143,
            Icmpv6Code::HomeAgentAddressDiscoveryRequest => 144,
            Icmpv6Code::HomeAgentAddressDiscoveryReply => 145,
            Icmpv6Code::MobilePrefixSolicitation => 146,
            Icmpv6Code::MobilePrefixAdvertisement => 147,
            Icmpv6Code::CertificationPathSolicitationMessage => 148,
            Icmpv6Code::CertificationPathAdvertisementMessage => 149,
            Icmpv6Code::ExperimentalMobilityProtocols => 150,
            Icmpv6Code::MulticastRouterAdvertisement => 151,
            Icmpv6Code::MulticastRouterSolicitation => 152,
            Icmpv6Code::MulticastRouterTermination => 153,
            Icmpv6Code::FMIPv6Messages => 154,
            Icmpv6Code::RPLControlMessage => 155,
            Icmpv6Code::ILNPv6LocatorUpdateMessage => 156,
            Icmpv6Code::DuplicateAddressRequest => 157,
            Icmpv6Code::DuplicateAddressConfirmation => 158,
            Icmpv6Code::MPLControlMessage => 159,
            Icmpv6Code::ExtendedEchoRequest => 160,
            Icmpv6Code::ExtendedEchoReply => 161,
            Icmpv6Code::Unknown(n) => n,
        }
    }
    
}

#[derive(Clone, Debug, PartialEq)]
pub struct Icmpv6Packet {
    pub icmpv6_type: Icmpv6Type,
    pub icmpv6_code: Icmpv6Code,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

impl Icmpv6Packet {
    pub(crate) fn from_pnet_packet(packet: &pnet::packet::icmpv6::Icmpv6Packet) -> Icmpv6Packet {
        Icmpv6Packet {
            icmpv6_type: Icmpv6Type::from_pnet_type(packet.get_icmpv6_type()),
            icmpv6_code: Icmpv6Code::from_u8(packet.get_icmpv6_code().0),
            checksum: packet.get_checksum(),
            payload: packet.payload().to_vec(),
        }
    }
}
