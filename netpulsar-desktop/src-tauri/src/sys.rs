use std::thread;
use std::sync::{Arc, Mutex};
use netpulsar_core::db;
use netpulsar_core::pcap;
use tauri::Manager;

pub fn init(handle: tauri::AppHandle) {
    // For background capture
    let netstat_strage_state = handle.state::<Arc<Mutex<netpulsar_core::net::stat::NetStatStrage>>>();
    let mut netstat_strage_capture = netstat_strage_state.inner().clone();
    // For stat updater
    let netstat_strage_state = handle.state::<Arc<Mutex<netpulsar_core::net::stat::NetStatStrage>>>();
    let mut netstat_strage_updater = netstat_strage_state.inner().clone();
    thread::spawn(move || {
        println!("[start] background_capture");
        let pcap_option = netpulsar_core::pcap::PacketCaptureOptions::default();
        let stop = Arc::new(Mutex::new(false));
        let result = pcap::start_background_capture(pcap_option.unwrap(), &stop, &mut netstat_strage_capture);
        println!("[stop] background_capture: {:?}", result);
    });
    // test thread
    /* thread::spawn(move || {
    println!("[start] test_thread");
    loop {
        match netstat_strage_updater.try_lock() {
            Ok(netstat_strage) => {
                println!("Total remotehost {}", netstat_strage.remote_hosts.keys().len());
            }
            Err(_) => {
                println!("netstat_strage_updater locked failed");
            }
        }
        thread::sleep(std::time::Duration::from_secs(2));
    }
    }); */
    thread::spawn(move || {
        println!("[start] stat_updater");
        netpulsar_core::net::dns::start_dns_updater(&mut netstat_strage_updater);
        println!("[stop] stat_updater");
    });

    match db::init_db() {
        Ok(_) => {
            println!("Database initialized");
            
            /* tauri::async_runtime::spawn(async move {
                
            }); */
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }
}

pub fn cleanup() {
    println!("Cleanup");
    match db::cleanup_db() {
        Ok(_) => {
            println!("Database cleaned up");
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }
}
