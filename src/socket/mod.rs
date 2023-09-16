use async_io::Async;
use socket2::{Domain, SockAddr, Socket as SystemSocket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::sync::Arc;

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
