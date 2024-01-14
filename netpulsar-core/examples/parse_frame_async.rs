#[tokio::main]
async fn main() {
    use xenet::packet::frame::Frame;
    //use std::sync::mpsc::{channel, Receiver, Sender};
    use tokio::sync::mpsc::{channel, Receiver, Sender};
    use std::sync::{Arc, Mutex};
    use std::thread;

    let (tx, mut rx): (Sender<Frame>, Receiver<Frame>) = channel(1);
    let stop = Arc::new(Mutex::new(false));
    let stop_handle = stop.clone();
    let pcap_option = netpulsar_core::pcap::PacketCaptureOptions::default();
    let pcap_handler = tokio::spawn(async move {
        netpulsar_core::pcap::start_capture_async(pcap_option.unwrap(), tx, &stop).await
    });
    let print_handler = tokio::spawn(async move {
        let mut count: usize = 0;
        while let Some(frame) = rx.recv().await {
            println!("frame: {:?}", frame);
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
    match pcap_handler.await {
        Ok(r) => {
            println!("pacp_handler: {:?}", r);
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }
    match print_handler.await {
        Ok(_) => {

        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }
}