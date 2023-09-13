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
    // Check and create install dir
    let install_dir: String = sys::get_install_path(define::NPCAP_INSTALL_DIR_NAME);
    if !std::path::Path::new(&install_dir).exists() {
        std::fs::create_dir_all(&install_dir)?;
    }
    let npcap_target_path: String = format!("{}\\{}", sys::get_install_path(define::NPCAP_INSTALL_DIR_NAME), define::NPCAP_INSTALLER_FILENAME);
    println!("Npcap installer path: {}", npcap_target_path);
    // Download npcap installer if not exists
    if !std::path::Path::new(&npcap_target_path).exists() {
        let mut response: reqwest::blocking::Response = reqwest::blocking::get(&npcap_installer_url)?;
        let mut file: File = File::create(&npcap_target_path)?;
        response.copy_to(&mut file)?;
        println!("Waiting for virus scan to complete (10 seconds) ...");
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
    // Checksum
    let mut file: File = File::open(&npcap_target_path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    let hash_result = hasher.finalize();
    let hash_result: String = format!("{:X}", hash_result);

    if hash_result != define::NPCAP_INSTALLER_HASH {
        println!("Downloaded file hash: {}", hash_result);
        return Err("Error: checksum failed...".into());
    }

    let exit_status: std::process::ExitStatus = RunasCommand::new(&npcap_target_path)
        .arg("/loopback_support=yes")
        .arg("/winpcap_mode=yes")
        .run()?;
    if !exit_status.success() {
        return Err("Error: Npcap installation failed !".into());
    }

    Ok(())
}

// Download and extract npcap sdk
pub fn install_npcap_sdk() -> Result<(), Box<dyn Error>> {
    let npcap_sdk_url = format!("{}{}", define::NPCAP_DIST_BASE_URL, define::NPCAP_SDK_FILENAME);
    // Check and create install dir
    let install_dir: String = sys::get_install_path(define::NPCAP_INSTALL_DIR_NAME);
    if !std::path::Path::new(&install_dir).exists() {
        std::fs::create_dir_all(&install_dir)?;
    }
    let npcap_sdk_target_path: String = format!("{}\\{}", sys::get_install_path(define::NPCAP_INSTALL_DIR_NAME), define::NPCAP_SDK_FILENAME);
    println!("Npcap sdk path: {}", npcap_sdk_target_path);
    // Download npcap sdk if not exists
    if !std::path::Path::new(&npcap_sdk_target_path).exists() {
        let mut response: reqwest::blocking::Response = reqwest::blocking::get(&npcap_sdk_url)?;
        let mut file: File = File::create(&npcap_sdk_target_path)?;
        response.copy_to(&mut file)?;
    }
    // Checksum
    let mut file: File = File::open(&npcap_sdk_target_path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    let hash_result = hasher.finalize();
    let hash_result: String = format!("{:X}", hash_result);

    if hash_result != define::NPCAP_SDK_HASH {
        println!("Downloaded file hash: {}", hash_result);
        return Err("Error: checksum failed...".into());
    }

    // Extract npcap sdk
    let npcap_sdk_extract_dir: String = format!("{}\\{}", sys::get_install_path(define::NPCAP_INSTALL_DIR_NAME), define::NPCAP_SDK_DIR_NAME);
    let mut archive: zip::ZipArchive<File> = zip::ZipArchive::new(File::open(&npcap_sdk_target_path)?)?;
    for i in 0..archive.len() {
        let mut file: zip::read::ZipFile = archive.by_index(i)?;
        let outpath: std::path::PathBuf = format!("{}\\{}", npcap_sdk_extract_dir, file.name()).into();
        if (&*file.name()).ends_with('/') {
            std::fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    std::fs::create_dir_all(&p)?;
                }
            }
            let mut outfile: File = std::fs::File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }

    // Add npcap sdk to LIB env var
    let os_bit: String = sys::get_os_bit();
    let lib_dir_path: String = if os_bit == "32-bit" {
        format!("{}\\{}", npcap_sdk_extract_dir, "Lib")
    }else {
        format!("{}\\{}", npcap_sdk_extract_dir, "Lib\\x64")
    };
    if !sys::check_env_lib_path(&lib_dir_path) {
        println!("Adding {} to LIB env var", lib_dir_path);
        sys::add_env_lib_path(&lib_dir_path);
    }
    Ok(())
}