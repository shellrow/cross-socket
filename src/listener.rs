use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use crate::option::PacketCaptureOptions;
use crate::packet::TcpIpFingerprint;
use crate::pcap::start_capture;

/// Listner
#[derive(Debug)]
pub struct Listner {
    pub options: PacketCaptureOptions,
    pub tx: Arc<Mutex<Sender<TcpIpFingerprint>>>,
    pub rx: Arc<Mutex<Receiver<TcpIpFingerprint>>>,
    pub stop: Arc<Mutex<bool>>,
    pub fingerprints: Arc<Mutex<Vec<TcpIpFingerprint>>>,
}

impl Listner {
    /// Create new Listner
    pub fn new(options: PacketCaptureOptions) -> Listner {
        let (tx, rx) = channel();
        let listener: Listner = Listner {
            options: options,
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
            stop: Arc::new(Mutex::new(false)),
            fingerprints: Arc::new(Mutex::new(Vec::new())),
        };
        listener
    }

    /// Get progress receiver
    pub fn get_receiver(&self) -> Arc<Mutex<Receiver<TcpIpFingerprint>>> {
        self.rx.clone()
    }
    
    /// Get stop handle
    pub fn get_stop_handle(&self) -> Arc<Mutex<bool>> {
        self.stop.clone()
    }

    // Get fingerprints
    pub fn get_fingerprints(&self) -> Vec<TcpIpFingerprint> {
        self.fingerprints.lock().unwrap().clone()
    }
    
    /// Start capture
    pub fn start(&self) {
        let options = self.options.clone();
        let fingerprints: Vec<TcpIpFingerprint> = start_capture(options, &self.tx, &self.stop);
        for fingerprint in fingerprints {
            self.fingerprints.lock().unwrap().push(fingerprint);
        }
    }
}
