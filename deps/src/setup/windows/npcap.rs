use std::error::Error;
use std::fs::File;
use sha2::{Sha256, Digest};
use privilege::runas::Command as RunasCommand;
use crate::setup::sys;
use crate::setup::define;

// Check if npcap is installed
pub fn is_npcap_installed() -> bool {
    sys::software_installed(define::NPCAP_SOFTWARE_NAME.to_owned())
}

// Download and Run npcap installer
pub fn install_npcap() -> Result<(), Box<dyn Error>> {
    let npcap_installer_url = format!("{}{}", define::NPCAP_DIST_BASE_URL, define::NPCAP_INSTALLER_FILENAME);
    // Download npcap installer if not exists
    if !std::path::Path::new(define::NPCAP_INSTALLER_FILENAME).exists() {
        let mut response: reqwest::blocking::Response = reqwest::blocking::get(&npcap_installer_url)?;
        let mut file: File = File::create(define::NPCAP_INSTALLER_FILENAME)?;
        response.copy_to(&mut file)?;
        println!("Waiting for virus scan to complete (10 seconds) ...");
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
    // Checksum
    let mut file: File = File::open(define::NPCAP_INSTALLER_FILENAME)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    let hash_result = hasher.finalize();
    let hash_result: String = format!("{:X}", hash_result);

    if hash_result != define::NPCAP_INSTALLER_HASH {
        println!("Downloaded file hash: {}", hash_result);
        return Err("Error: checksum failed...".into());
    }

    let exit_status: std::process::ExitStatus = RunasCommand::new(define::NPCAP_INSTALLER_FILENAME)
        .arg("/loopback_support=yes")
        .arg("/winpcap_mode=yes")
        .run()?;
    if !exit_status.success() {
        return Err("Error: Npcap installation failed !".into());
    }

    Ok(())
}
