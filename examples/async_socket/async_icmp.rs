use async_io;
use cross_socket::packet::ethernet::EtherType;
use cross_socket::packet::PacketFrame;
use futures::executor::ThreadPool;
use futures::stream::{self, StreamExt};
use futures::task::SpawnExt;
use ipnet::Ipv4Net;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use cross_socket::datalink::interface::Interface;
use cross_socket::packet::icmp::IcmpPacketBuilder;
use cross_socket::packet::ip::IpNextLevelProtocol;
use cross_socket::pcap::listener::Listner;
use cross_socket::pcap::PacketCaptureOptions;
use cross_socket::socket::{AsyncSocket, IpVersion, SocketOption, SocketType};

// Send ICMP Echo Request packets asynchronously
async fn send_icmp_echo_packets(
    socket: &AsyncSocket,
    src_ip: Ipv4Addr,
    target_hosts: Vec<Ipv4Addr>,
) {
    let fut_host = stream::iter(target_hosts).for_each_concurrent(50, |dst_ip| {
        let socket_addr = SocketAddr::new(IpAddr::V4(dst_ip), 0);
        async move {
            // Packet builder for ICMP Echo Request
            let mut packet_builder = IcmpPacketBuilder::new(src_ip, dst_ip);
            packet_builder.icmp_type = cross_socket::packet::icmp::IcmpType::EchoRequest;
            // Build ICMP Echo Request packet
            let mut icmp_packet = packet_builder.build();
            match socket.send_to(&mut icmp_packet, socket_addr).await {
                Ok(_) => {}
                Err(_) => {}
            }
        }
    });
    fut_host.await;
}

fn main() {
    async_io::block_on(async_main());
}

// Scan your local network for active hosts using ICMP echo requests.
async fn async_main() {
    let interface: Interface = cross_socket::datalink::interface::get_default_interface().unwrap();
    let src_ip: Ipv4Addr = interface.ipv4[0].addr;
    let net: Ipv4Net = Ipv4Net::new(src_ip, 24).unwrap();
    let nw_addr = Ipv4Net::new(net.network(), 24).unwrap();
    let hosts: Vec<Ipv4Addr> = nw_addr.hosts().collect();
    let socket_option = SocketOption {
        ip_version: IpVersion::V4,
        socket_type: SocketType::Raw,
        protocol: Some(IpNextLevelProtocol::Icmp),
        timeout: None,
        ttl: None,
        non_blocking: false,
    };
    let socket: AsyncSocket = AsyncSocket::new(socket_option).unwrap();

    let mut capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: interface.index,
        interface_name: interface.name,
        src_ips: HashSet::new(),
        dst_ips: HashSet::new(),
        src_ports: HashSet::new(),
        dst_ports: HashSet::new(),
        ether_types: [EtherType::Ipv4].iter().cloned().collect(),
        ip_protocols: [IpNextLevelProtocol::Icmp].iter().cloned().collect(),
        duration: Duration::from_secs(30),
        promiscuous: false,
        store: true,
        store_limit: 1000,
        receive_undefined: false,
    };
    for target in hosts.clone() {
        capture_options.src_ips.insert(IpAddr::V4(target));
    }
    let listener: Listner = Listner::new(capture_options);
    let stop_handle = listener.get_stop_handle();
    let packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::new(Mutex::new(vec![]));
    let receive_packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::clone(&packets);

    let executor = ThreadPool::new().unwrap();
    let future = async move {
        listener.start();
        for p in listener.get_packets() {
            receive_packets.lock().unwrap().push(p);
        }
    };
    let lisner_handle: futures::future::RemoteHandle<()> =
        executor.spawn_with_handle(future).unwrap();
    // Wait for listener to start
    thread::sleep(Duration::from_millis(1));

    // Send probe packets
    send_icmp_echo_packets(&socket, src_ip, hosts).await;
    thread::sleep(Duration::from_millis(100));
    *stop_handle.lock().unwrap() = true;
    // Wait for listener to complete task
    lisner_handle.await;

    // Print captured packets
    println!("Up hosts: ");
    for f in packets.lock().unwrap().iter() {
        if let Some(ipv4_packet) = &f.ipv4_packet {
            if ipv4_packet.source == src_ip {
                continue;
            }
            if let Some(icmp_packet) = &f.icmp_packet {
                if icmp_packet.icmp_type == cross_socket::packet::icmp::IcmpType::EchoReply {
                    println!("Echo reply from {}", ipv4_packet.source);
                }
            }
        }
    }
}
