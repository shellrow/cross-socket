use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use tauri::Manager;
use xenet::packet::frame::Frame;
use crossbeam_channel::{bounded, Receiver as CrossbeamReceiver, Sender as CrossbeamSender};
use netpulsar_core::netstat::{ProcessSocketInfo, SocketInfoOption};
use netpulsar_core::pcap::CaptureReport;
use netpulsar_core::models::packet::PacketFrame;

#[tauri::command]
pub fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
pub async fn start_packet_capture(app_handle: tauri::AppHandle) -> CaptureReport {
    let mut report = CaptureReport::new();
    let (tx, rx): (Sender<PacketFrame>, Receiver<PacketFrame>) = channel();
    let stop = Arc::new(Mutex::new(false));
    let stop_handle = stop.clone();
    let pcap_option = netpulsar_core::pcap::PacketCaptureOptions::default();
    let pacp_handler = thread::spawn(move || {
        netpulsar_core::pcap::start_capture(pcap_option.unwrap(), tx, &stop)
    });
    let stop_pcap_event = app_handle.listen_global("stop_pcap", move |event| {
        println!("got stop_pcap with payload {:?}", event.payload());
        match stop_handle.lock() {
            Ok(mut stop) => {
                *stop = true;
            }
            Err(e) => {
                eprintln!("Error: {:?}", e);
            }
        }
    });
    let print_handler = thread::spawn(move || {
        while let Ok(frame) = rx.recv() {
            match app_handle.emit_all("packet_frame", frame) {
                Ok(_) => {

                }
                Err(e) => {
                    println!("Error: {:?}", e);
                }
            }
        }
        app_handle.unlisten(stop_pcap_event);
    });
    /* thread::sleep(std::time::Duration::from_secs(30));
    match stop_handle.lock() {
        Ok(mut stop) => {
            *stop = true;
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }   */  
    match pacp_handler.join() {
        Ok(r) => {
            println!("pacp_handler: {:?}", r);
            report = r;
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }
    match print_handler.join() {
        Ok(_) => {
            
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }
    report
}

#[tauri::command]
pub async fn start_packet_capture_crossbeam(app_handle: tauri::AppHandle) -> CaptureReport {
    let mut report = CaptureReport::new();
    let (tx, rx): (CrossbeamSender<Frame>, CrossbeamReceiver<Frame>) = bounded(1);
    let stop = Arc::new(Mutex::new(false));
    let stop_handle = stop.clone();
    let pcap_option = netpulsar_core::pcap::PacketCaptureOptions::default();
    let pacp_handler = thread::spawn(move || {
        netpulsar_core::pcap::start_capture_crossbeam(pcap_option.unwrap(), tx, &stop)
    });
    let print_handler = thread::spawn(move || {
        let mut count: usize = 0;
        while let Ok(frame) = rx.recv() {
            match app_handle.emit_all("packet_frame", frame) {
                Ok(_) => {

                }
                Err(e) => {
                    println!("Error: {:?}", e);
                }
            }
            count += 1;
        }
        println!("count: {}", count);
    });
    thread::sleep(std::time::Duration::from_secs(30));
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
            report = r;
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }
    match print_handler.join() {
        Ok(_) => {
            
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }
    report
}

#[tauri::command]
pub fn get_netstat(opt: SocketInfoOption) -> Vec<ProcessSocketInfo> {
    netpulsar_core::netstat::get_netstat(opt)
}
