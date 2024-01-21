use netpulsar_core::netstat::SocketInfoOption;

extern crate netpulsar_core;

#[test]
fn show_netstat() {
    let netstat = netpulsar_core::netstat::get_netstat(SocketInfoOption::default());
    for ns in netstat.iter() {
        println!("{:?}", ns);
    }
    assert!(netstat.len() > 0);
}

#[test]
fn test_get_os_type() {
    let os_type = netpulsar_core::sys::get_os_type();
    println!("os_type: {}", os_type);
    assert!(os_type.len() > 0);
}

#[test]
fn test_get_sysdate() {
    let sysdate = netpulsar_core::sys::get_sysdate();
    println!("sysdate: {}", sysdate);
    assert!(sysdate.len() > 0);
}

#[test]
fn test_pcap() {
    use netpulsar_core::models::packet::PacketFrame;
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::sync::{Arc, Mutex};
    use std::thread;

    let (tx, rx): (Sender<PacketFrame>, Receiver<PacketFrame>) = channel();
    let stop = Arc::new(Mutex::new(false));
    let stop_handle = stop.clone();
    let pcap_option = netpulsar_core::pcap::PacketCaptureOptions::default();
    let pacp_handler = thread::spawn(move || {
        netpulsar_core::pcap::start_capture(pcap_option.unwrap(), tx, &stop)
    });
    /* let print_handler = thread::spawn(move || {
        let mut count: usize = 0;
        while let Ok(frame) = rx.recv() {
            println!("frame: {:?}", frame);
            count += 1;
        }
        println!("count: {}", count);
    }); */
    // capture packet to 5 seconds
    let start = std::time::Instant::now();
    let mut count: usize = 0;
    loop {
        while let Ok(frame) = rx.recv() {
            println!("frame: {:?}", frame);
            count += 1;
        }
        if start.elapsed().as_secs() >= 5 {
            println!("count: {}", count);
            break;
        }
    }
    //thread::sleep(std::time::Duration::from_secs(30));
    match stop_handle.lock() {
        Ok(mut stop) => {
            *stop = true;
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }    
    
    match pacp_handler.join() {
        Ok(r) => {
            println!("pacp_handler: {:?}", r);
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }
    /* match print_handler.join() {
        Ok(_) => {
            
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    } */
}
