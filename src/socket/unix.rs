
use crate::packet::ip::IpNextLevelProtocol;

use super::{SocketOption, IpVersion, SocketType};

pub fn check_socket_option(socket_option: SocketOption) -> Result<(), String> {
    match socket_option.ip_version {
        IpVersion::V4 => {
            match socket_option.socket_type {
                SocketType::Raw => {
                    match socket_option.protocol {
                        IpNextLevelProtocol::Icmp => Ok(()),
                        IpNextLevelProtocol::Tcp => Ok(()),
                        IpNextLevelProtocol::Udp => Ok(()),
                        _ => Err(String::from("Invalid protocol")),
                    }
                }
                SocketType::Dgram => {
                    match socket_option.protocol {
                        IpNextLevelProtocol::Icmp => Ok(()),
                        IpNextLevelProtocol::Udp => Ok(()),
                        _ => Err(String::from("Invalid protocol")),
                    }
                }
                SocketType::Stream => {
                    match socket_option.protocol {
                        IpNextLevelProtocol::Tcp => Ok(()),
                        _ => Err(String::from("Invalid protocol")),
                    }
                }
            }
        }
        IpVersion::V6 => {
            match socket_option.socket_type {
                SocketType::Raw => {
                    match socket_option.protocol {
                        IpNextLevelProtocol::Icmpv6 => Ok(()),
                        IpNextLevelProtocol::Tcp => Ok(()),
                        IpNextLevelProtocol::Udp => Ok(()),
                        _ => Err(String::from("Invalid protocol")),
                    }
                }
                SocketType::Dgram => {
                    match socket_option.protocol {
                        IpNextLevelProtocol::Icmpv6 => Ok(()),
                        IpNextLevelProtocol::Udp => Ok(()),
                        _ => Err(String::from("Invalid protocol")),
                    }
                }
                SocketType::Stream => {
                    match socket_option.protocol {
                        IpNextLevelProtocol::Tcp => Ok(()),
                        _ => Err(String::from("Invalid protocol")),
                    }
                }
            }
        }
    }
}