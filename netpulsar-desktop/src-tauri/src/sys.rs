use std::thread;
use std::sync::{Arc, Mutex};
use netpulsar_core::db;
use netpulsar_core::pcap;

pub fn init(_handle: tauri::AppHandle) {
    match db::init_db() {
        Ok(_) => {
            println!("Database initialized");
            thread::spawn(move || {
                println!("[start] background_capture");
                let pcap_option = netpulsar_core::pcap::PacketCaptureOptions::default();
                let stop = Arc::new(Mutex::new(false));
                let result = pcap::start_background_capture(pcap_option.unwrap(), &stop);
                println!("[stop] background_capture: {:?}", result);
            });
            tauri::async_runtime::spawn(async move {
                println!("[start] stat_updater");
                db::stat::start_stat_updater().await;
                println!("[stop] stat_updater");
            });
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
