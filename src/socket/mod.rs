mod shared;
pub(crate) use shared::*;

#[cfg(not(target_os = "windows"))]
mod unix;
#[cfg(not(target_os = "windows"))]
pub(crate) use unix::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub(crate) use windows::*;

use async_io::Async;
use socket2::{Domain, SockAddr, Socket as SystemSocket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::sync::Arc;

use crate::packet::PacketInfo;
use crate::packet::ip::IpNextLevelProtocol;

#[derive(Clone, Debug)]
pub enum IpVersion {
    V4,
    V6,
}

impl IpVersion {
    pub fn version_u8(&self) -> u8 {
        match self {
            IpVersion::V4 => 4,
            IpVersion::V6 => 6,
        }
    }
    pub fn is_ipv4(&self) -> bool {
        match self {
            IpVersion::V4 => true,
            IpVersion::V6 => false,
        }
    }
    pub fn is_ipv6(&self) -> bool {
        match self {
            IpVersion::V4 => false,
            IpVersion::V6 => true,
        }
    }
    pub(crate) fn to_domain(&self) -> Domain {
        match self {
            IpVersion::V4 => Domain::IPV4,
            IpVersion::V6 => Domain::IPV6,
        }
    }
}

#[derive(Clone, Debug)]
pub enum SocketType {
    Raw,
    Dgram,
    Stream,
}

impl SocketType {
    pub(crate) fn to_type(&self) -> Type {
        match self {
            SocketType::Raw => Type::RAW,
            SocketType::Dgram => Type::DGRAM,
            SocketType::Stream => Type::STREAM,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SocketOption {
    pub ip_version: IpVersion,
    pub socket_type: SocketType,
    pub protocol: IpNextLevelProtocol,
}

impl SocketOption {
    pub fn new(ip_version: IpVersion, socket_type: SocketType, protocol: IpNextLevelProtocol) -> SocketOption {
        SocketOption {
            ip_version,
            socket_type,
            protocol,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AsyncSocket {
    inner: Arc<Async<SystemSocket>>,
}

impl AsyncSocket {
    pub fn new(socket_option: SocketOption) -> io::Result<AsyncSocket> {
        match check_socket_option(socket_option.clone()) {
            Ok(_) => (),
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
        }
        let socket: SystemSocket = SystemSocket::new(socket_option.ip_version.to_domain(), socket_option.socket_type.to_type(), Some(socket_option.protocol.to_socket_protocol()))?;
        socket.set_nonblocking(true)?;
        Ok(AsyncSocket {
            inner: Arc::new(Async::new(socket)?),
        })
    }
    pub async fn send_to(&self, buf: &mut [u8], target: &SockAddr) -> io::Result<usize> {
        loop {
            self.inner.writable().await?;
            match self
                .inner
                .write_with(|inner| inner.send_to(buf, target))
                .await
            {
                Ok(n) => return Ok(n),
                Err(_) => continue,
            }
        }
    }
    pub async fn receive(&self, buf: &mut [MaybeUninit<u8>]) -> io::Result<usize> {
        loop {
            self.inner.readable().await?;
            match self.inner.read_with(|inner| inner.recv(buf)).await {
                Ok(result) => return Ok(result),
                Err(_) => continue,
            }
        }
    }
    pub async fn receive_from(
        &self,
        buf: &mut [MaybeUninit<u8>],
    ) -> io::Result<(usize, SockAddr)> {
        loop {
            self.inner.readable().await?;
            match self.inner.read_with(|inner| inner.recv_from(buf)).await {
                Ok(result) => return Ok(result),
                Err(_) => continue,
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Socket {
    inner: Arc<SystemSocket>,
}

impl Socket {
    pub fn new(socket_option: SocketOption) -> io::Result<Socket> {
        match check_socket_option(socket_option.clone()) {
            Ok(_) => (),
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
        }
        let socket: SystemSocket = SystemSocket::new(socket_option.ip_version.to_domain(), socket_option.socket_type.to_type(), Some(socket_option.protocol.to_socket_protocol()))?;
        socket.set_nonblocking(true)?;
        Ok(Socket {
            inner: Arc::new(socket),
        })
    }
    pub fn send_to(&self, buf: &[u8], target: &SockAddr) -> io::Result<usize> {
        loop {
            match self.inner.send_to(buf, target) {
                Ok(n) => return Ok(n),
                Err(_) => continue,
            }
        }
    }
    pub fn receive(&self, buf: &mut [MaybeUninit<u8>]) -> io::Result<usize> {
        loop {
            match self.inner.recv(buf) {
                Ok(result) => return Ok(result),
                Err(_) => continue,
            }
        }
    }
    pub fn receive_from(&self, buf: &mut [MaybeUninit<u8>]) -> io::Result<(usize, SockAddr)> {
        loop {
            match self.inner.recv_from(buf) {
                Ok(result) => return Ok(result),
                Err(_) => continue,
            }
        }
    }
}

pub struct DataLinkSocket {
    pub interface: crate::interface::Interface,
    sender: Box<dyn pnet::datalink::DataLinkSender>,
    receiver: Box<dyn pnet::datalink::DataLinkReceiver>,
}

impl DataLinkSocket {
    pub fn new(interface: crate::interface::Interface, promiscuous: bool) -> io::Result<DataLinkSocket> {
        let interfaces = pnet::datalink::interfaces();
        let network_interface = match interfaces
        .into_iter()
        .filter(|network_interface: &pnet::datalink::NetworkInterface| {
            network_interface.index == interface.index
        })
        .next()
        {
            Some(network_interface) => network_interface,
            None => return Err(io::Error::new(io::ErrorKind::Other, "Network Interface not found")),
        };
        let config = pnet::datalink::Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            read_timeout: None,
            write_timeout: None,
            channel_type: pnet::datalink::ChannelType::Layer2,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
            promiscuous: promiscuous,
        };
        let (tx, rx) = match pnet::datalink::channel(&network_interface, config) {
            Ok(pnet::datalink::Channel::Ethernet(sender, receiver)) => (sender, receiver),
            Ok(_) => return Err(io::Error::new(io::ErrorKind::Other, "Not an Ethernet interface")),
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
        };
        Ok(DataLinkSocket {
            interface: interface,
            sender: tx,
            receiver: rx,
        })
    }
    pub fn send(&mut self, packet_info: PacketInfo) -> io::Result<usize> {
        build_and_send_packet(&mut self.sender, packet_info)
    }
    pub fn send_to(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.sender.send_to(buf, None) {
            Some(res) => {
                match res {
                    Ok(_) => return Ok(buf.len()),
                    Err(_) => return Err(io::Error::new(io::ErrorKind::Other, "Failed to send packet")),
                }
            },
            None => Err(io::Error::new(io::ErrorKind::Other, "Failed to send packet")),
        }
    }
    pub fn build_and_send(&mut self, num_packets: usize, packet_size: usize, func: &mut dyn FnMut(&mut [u8])) -> io::Result<()> {
        match self.sender.build_and_send(num_packets, packet_size, func) {
            Some(res) => {
                match res {
                    Ok(_) => return Ok(()),
                    Err(_) => return Err(io::Error::new(io::ErrorKind::Other, "Failed to send packet")),
                }
            },
            None => Err(io::Error::new(io::ErrorKind::Other, "Failed to send packet")),
        }
    }
    pub fn receive(&mut self) -> io::Result<&[u8]> {
        match self.receiver.next() {
            Ok(packet) => {
                Ok(packet)
            },
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Failed to receive packet")),
        }
    }
}
