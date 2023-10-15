use cross_socket::pcap::listener::Listner;
use cross_socket::pcap::PacketCaptureOptions;
use default_net::Interface;
use std::collections::HashSet;
use std::thread;
use std::time::Duration;
use std::env;

// Start capturing all packets (TCP, UDP, ICMP only) on the default interface (or the interface specified by user)
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
    // No filter. Capture all packets.
    let capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: interface.index,
        interface_name: interface.name.clone(),
        src_ips: HashSet::new(),
        dst_ips: HashSet::new(),
        src_ports: HashSet::new(),
        dst_ports: HashSet::new(),
        ether_types: HashSet::new(),
        ip_protocols: HashSet::new(),
        duration: Duration::from_secs(30),
        read_timeout: Duration::from_secs(2),
        promiscuous: false,
        store: false,
        store_limit: 0,
        receive_undefined: true,
        use_tun: interface.is_tun(),
        loopback: interface.is_loopback(),
    };
    // Create new listener
    let listener: Listner = Listner::new(capture_options);
    let rx = listener.get_receiver();
    // Start capturing packets
    let handle = thread::spawn(move || listener.start());
    // Print captured packets
    while let Ok(msg) = rx.lock().unwrap().recv() {
        println!("----{}--------", msg.capture_info.capture_no);
        println!("{:?}", msg);
    }
    let _result = handle.join().unwrap();
}
