mod shared;
pub(crate) use shared::*;

#[cfg(not(target_os = "windows"))]
mod unix;
#[cfg(not(target_os = "windows"))]
pub use unix::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

use async_io::Async;
use socket2::{Domain, SockAddr, Socket as SystemSocket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::{SocketAddr, Shutdown};
use std::sync::Arc;
use std::time::Duration;

use crate::packet::builder::PacketBuildOption;
use crate::packet::ip::IpNextLevelProtocol;

/// IP version. IPv4 or IPv6
#[derive(Clone, Debug)]
pub enum IpVersion {
    V4,
    V6,
}

impl IpVersion {
    /// IP Version number as u8
    pub fn version_u8(&self) -> u8 {
        match self {
            IpVersion::V4 => 4,
            IpVersion::V6 => 6,
        }
    }
    /// Return true if IP version is IPv4
    pub fn is_ipv4(&self) -> bool {
        match self {
            IpVersion::V4 => true,
            IpVersion::V6 => false,
        }
    }
    /// Return true if IP version is IPv6
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

/// Socket type
#[derive(Clone, Debug)]
pub enum SocketType {
    /// Raw socket
    Raw,
    /// Datagram socket. Usualy used for UDP.
    Dgram,
    /// Stream socket. Used for TCP.
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

/// Socket option
#[derive(Clone, Debug)]
pub struct SocketOption {
    /// IP version
    pub ip_version: IpVersion,
    /// Socket type
    pub socket_type: SocketType,
    /// Protocol. TCP, UDP, ICMP, etc.
    pub protocol: Option<IpNextLevelProtocol>,
    /// Timeout
    pub timeout: Option<u64>,
    /// TTL or Hop Limit
    pub ttl: Option<u32>,
    /// Non-blocking mode
    pub non_blocking: bool,
}

impl SocketOption {
    /// Constructs a new SocketOption
    pub fn new(
        ip_version: IpVersion,
        socket_type: SocketType,
        protocol: Option<IpNextLevelProtocol>,
    ) -> SocketOption {
        SocketOption {
            ip_version,
            socket_type,
            protocol,
            timeout: None,
            ttl: None,
            non_blocking: false,
        }
    }
}

/// Async socket. Provides cross-platform async adapter for system’s socket.
#[derive(Clone, Debug)]
pub struct AsyncSocket {
    inner: Arc<Async<SystemSocket>>,
}

impl AsyncSocket {
    /// Constructs a new AsyncSocket
    pub fn new(socket_option: SocketOption) -> io::Result<AsyncSocket> {
        match check_socket_option(socket_option.clone()) {
            Ok(_) => (),
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
        }
        let socket: SystemSocket = if let Some(protocol) = socket_option.protocol {
            SystemSocket::new(
                socket_option.ip_version.to_domain(),
                socket_option.socket_type.to_type(),
                Some(protocol.to_socket_protocol()),
            )?
        } else {
            SystemSocket::new(
                socket_option.ip_version.to_domain(),
                socket_option.socket_type.to_type(),
                None,
            )?
        };
        socket.set_nonblocking(true)?;
        Ok(AsyncSocket {
            inner: Arc::new(Async::new(socket)?),
        })
    }
    /// Send packet
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            self.inner.writable().await?;
            match self.inner.write_with(|inner| inner.send(buf)).await {
                Ok(n) => return Ok(n),
                Err(_) => continue,
            }
        }
    }
    /// Send packet to target
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        let target: SockAddr = SockAddr::from(target);
        loop {
            self.inner.writable().await?;
            match self
                .inner
                .write_with(|inner| inner.send_to(buf, &target))
                .await
            {
                Ok(n) => return Ok(n),
                Err(_) => continue,
            }
        }
    }
    /// Receive packet
    pub async fn receive(&self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        loop {
            self.inner.readable().await?;
            match self.inner.read_with(|inner| inner.recv(recv_buf)).await {
                Ok(result) => return Ok(result),
                Err(_) => continue,
            }
        }
    }
    /// Receive packet with sender address
    pub async fn receive_from(&self, buf: &mut Vec<u8>) -> io::Result<(usize, SocketAddr)> {
        let recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        loop {
            self.inner.readable().await?;
            match self
                .inner
                .read_with(|inner| inner.recv_from(recv_buf))
                .await
            {
                Ok(result) => {
                    let (n, addr) = result;
                    match addr.as_socket() {
                        Some(addr) => return Ok((n, addr)),
                        None => continue,
                    }
                }
                Err(_) => continue,
            }
        }
    }
    /// Bind socket to address
    pub async fn bind(&self, addr: SocketAddr) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(addr);
        self.inner.writable().await?;
        self.inner.write_with(|inner| inner.bind(&addr)).await
    }
    /// Set receive timeout
    pub async fn set_receive_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.writable().await?;
        self.inner
            .write_with(|inner| inner.set_read_timeout(timeout))
            .await
    }
    /// Set TTL or Hop Limit
    pub async fn set_ttl(&self, ttl: u32, ip_version: IpVersion) -> io::Result<()> {
        self.inner.writable().await?;
        match ip_version {
            IpVersion::V4 => self.inner.write_with(|inner| inner.set_ttl(ttl)).await,
            IpVersion::V6 => {
                self.inner
                    .write_with(|inner| inner.set_unicast_hops_v6(ttl))
                    .await
            }
        }
    }
    /// Initiate TCP connection
    pub async fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(addr);
        self.inner.writable().await?;
        self.inner.write_with(|inner| inner.connect(&addr)).await
    }
    /// Shutdown TCP connection
    pub async fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.writable().await?;
        self.inner.write_with(|inner| inner.shutdown(how)).await
    }
    /// Listen TCP connection
    pub async fn listen(&self, backlog: i32) -> io::Result<()> {
        self.inner.writable().await?;
        self.inner.write_with(|inner| inner.listen(backlog)).await
    }
    /// Accept TCP connection
    pub async fn accept(&self) -> io::Result<(AsyncSocket, SocketAddr)> {
        self.inner.readable().await?;
        match self.inner.read_with(|inner| inner.accept()).await {
            Ok((socket, addr)) => {
                let socket = AsyncSocket {
                    inner: Arc::new(Async::new(socket)?),
                };
                Ok((socket, addr.as_socket().unwrap()))
            }
            Err(e) => Err(e),
        }
    }
    /// Get peer address
    pub async fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.writable().await?;
        match self.inner.read_with(|inner| inner.peer_addr()).await {
            Ok(addr) => Ok(addr.as_socket().unwrap()),
            Err(e) => Err(e),
        }
    }
    /// Get local address
    pub async fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.writable().await?;
        match self.inner.read_with(|inner| inner.local_addr()).await {
            Ok(addr) => Ok(addr.as_socket().unwrap()),
            Err(e) => Err(e),
        }
    }
}

/// Socket. Provides cross-platform adapter for system’s socket.
#[derive(Clone, Debug)]
pub struct Socket {
    inner: Arc<SystemSocket>,
}

impl Socket {
    /// Constructs a new Socket
    pub fn new(socket_option: SocketOption) -> io::Result<Socket> {
        match check_socket_option(socket_option.clone()) {
            Ok(_) => (),
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
        }
        let socket: SystemSocket = if let Some(protocol) = socket_option.protocol {
            SystemSocket::new(
                socket_option.ip_version.to_domain(),
                socket_option.socket_type.to_type(),
                Some(protocol.to_socket_protocol()),
            )?
        } else {
            SystemSocket::new(
                socket_option.ip_version.to_domain(),
                socket_option.socket_type.to_type(),
                None,
            )?
        };
        if socket_option.non_blocking {
            socket.set_nonblocking(true)?;
        }
        Ok(Socket {
            inner: Arc::new(socket),
        })
    }
    /// Send packet to target
    pub fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        let target: SockAddr = SockAddr::from(target);
        match self.inner.send_to(buf, &target) {
            Ok(n) => Ok(n),
            Err(e) => Err(e),
        }
    }
    /// Receive packet
    pub fn receive(&self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        match self.inner.recv(recv_buf) {
            Ok(result) => Ok(result),
            Err(e) => Err(e),
        }
    }
    /// Receive packet with sender address
    pub fn receive_from(&self, buf: &mut Vec<u8>) -> io::Result<(usize, SocketAddr)> {
        let recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        match self.inner.recv_from(recv_buf) {
            Ok(result) => {
                let (n, addr) = result;
                match addr.as_socket() {
                    Some(addr) => return Ok((n, addr)),
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "Invalid socket address",
                        ))
                    }
                }
            }
            Err(e) => Err(e),
        }
    }
    /// Bind socket to address
    pub fn bind(&self, addr: SocketAddr) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(addr);
        self.inner.bind(&addr)
    }
    /// Set receive timeout
    pub fn set_receive_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }
    /// Set TTL or Hop Limit
    pub fn set_ttl(&self, ttl: u32, ip_version: IpVersion) -> io::Result<()> {
        match ip_version {
            IpVersion::V4 => self.inner.set_ttl(ttl),
            IpVersion::V6 => self.inner.set_unicast_hops_v6(ttl),
        }
    }
    /// Initiate TCP connection
    pub fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        let addr: SockAddr = SockAddr::from(addr);
        self.inner.connect(&addr)
    }
    /// Shutdown TCP connection
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }
    /// Listen TCP connection
    pub fn listen(&self, backlog: i32) -> io::Result<()> {
        self.inner.listen(backlog)
    }
    /// Accept TCP connection
    pub fn accept(&self) -> io::Result<(Socket, SocketAddr)> {
        match self.inner.accept() {
            Ok((socket, addr)) => Ok((Socket { inner: Arc::new(socket) }, addr.as_socket().unwrap())),
            Err(e) => Err(e),
        }
    }
    /// Get peer address
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self.inner.peer_addr() {
            Ok(addr) => Ok(addr.as_socket().unwrap()),
            Err(e) => Err(e),
        }
    }
    /// Get local address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self.inner.local_addr() {
            Ok(addr) => Ok(addr.as_socket().unwrap()),
            Err(e) => Err(e),
        }
    }
}

/// Cross-platform raw socket.
/// Enables to send and receive packets with custom headers.
pub struct DataLinkSocket {
    pub interface: crate::datalink::interface::Interface,
    sender: Box<dyn pnet::datalink::DataLinkSender>,
    receiver: Box<dyn pnet::datalink::DataLinkReceiver>,
}

impl DataLinkSocket {
    /// Constructs a new DataLinkSocket
    pub fn new(
        interface: crate::datalink::interface::Interface,
        promiscuous: bool,
    ) -> io::Result<DataLinkSocket> {
        let interfaces = pnet::datalink::interfaces();
        let network_interface = match interfaces
            .into_iter()
            .filter(|network_interface: &pnet::datalink::NetworkInterface| {
                network_interface.index == interface.index
            })
            .next()
        {
            Some(network_interface) => network_interface,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Network Interface not found",
                ))
            }
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
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Not an Ethernet interface",
                ))
            }
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
        };
        Ok(DataLinkSocket {
            interface: interface,
            sender: tx,
            receiver: rx,
        })
    }
    /// Build packet from PacketBuildOption and send it
    pub fn send(&mut self, packet_builder: PacketBuildOption) -> io::Result<usize> {
        build_and_send_packet(&mut self.sender, packet_builder)
    }
    /// Send packet
    pub fn send_to(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.sender.send_to(buf, None) {
            Some(res) => match res {
                Ok(_) => return Ok(buf.len()),
                Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
            },
            None => Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to send packet",
            )),
        }
    }
    /// Build and send packet. This is useful when you want to send packet with custom build function.
    pub fn build_and_send(
        &mut self,
        num_packets: usize,
        packet_size: usize,
        func: &mut dyn FnMut(&mut [u8]),
    ) -> io::Result<()> {
        match self.sender.build_and_send(num_packets, packet_size, func) {
            Some(res) => match res {
                Ok(_) => return Ok(()),
                Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
            },
            None => Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to send packet",
            )),
        }
    }
    /// Receive packet
    pub fn receive(&mut self) -> io::Result<&[u8]> {
        match self.receiver.next() {
            Ok(packet) => Ok(packet),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }
}
