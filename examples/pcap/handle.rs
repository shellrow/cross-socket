use cross_socket::packet::ethernet::EtherType;
use cross_socket::packet::ip::IpNextLevelProtocol;
use cross_socket::pcap::listener::Listner;
use cross_socket::pcap::PacketCaptureOptions;
use default_net::Interface;
use std::collections::HashSet;
use std::thread;
use std::time::Duration;
use std::env;

// Start capturing TCP packets on the default interface (or the interface specified by user)
// Filter: Protocol: TCP only, Ports: 22, 80, 443, 4433, 5000, 8080, 8443, 8888, 9000, 9443
// Stop after 10 seconds using the stop handle
fn main() {
    let interface: Interface = match env::args().nth(1) {
        Some(n) => {
            // Use interface specified by user
            let interfaces: Vec<Interface> = default_net::get_interfaces();
            let interface: Interface = interfaces
                .into_iter()
                .find(|interface| interface.name == n)
                .expect("Failed to get interface information");
            interface
        },
        None => {
            // Use default interface
            default_net::get_default_interface().expect("Failed to get default interface information")
        }
    };
    // Filter: Protocol: TCP only, Ports: 22, 80, 443, 4433, 5000, 8080, 8443, 8888, 9000, 9443
    let capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: interface.index,
        interface_name: interface.name.clone(),
        src_ips: HashSet::new(),
        dst_ips: HashSet::new(),
        src_ports: [22, 80, 443, 4433, 5000, 8080, 8443, 8888, 9000, 9443]
            .iter()
            .cloned()
            .collect(),
        dst_ports: [22, 80, 443, 4433, 5000, 8080, 8443, 8888, 9000, 9443]
            .iter()
            .cloned()
            .collect(),
        ether_types: [EtherType::Ipv4].iter().cloned().collect(),
        ip_protocols: [IpNextLevelProtocol::Tcp].iter().cloned().collect(),
        duration: Duration::from_secs(30),
        read_timeout: Duration::from_secs(2),
        promiscuous: false,
        store: false,
        store_limit: 0,
        receive_undefined: false,
        use_tun: interface.is_tun(),
        loopback: interface.is_loopback(),
    };
    // Create new listener
    let listener: Listner = Listner::new(capture_options);
    let rx = listener.get_receiver();
    let stop = listener.get_stop_handle();
    // Stop after 10 seconds
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(10));
        *stop.lock().unwrap() = true;
    });
    // Start capturing packets
    let handle = thread::spawn(move || listener.start());
    // Print captured packets
    while let Ok(msg) = rx.lock().unwrap().recv() {
        println!("----{}--------", msg.capture_info.capture_no);
        println!("{:?}", msg);
    }
    let _result = handle.join().unwrap();
}
