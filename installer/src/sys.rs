use std::{env, fs, io};
use std::path::{PathBuf, Path};

use crate::define;

#[cfg(target_os = "windows")]
pub fn get_os_type() -> String{"windows".to_owned()}

#[cfg(target_os = "linux")]
pub fn get_os_type() -> String{"linux".to_owned()}

#[cfg(target_os = "macos")]
pub fn get_os_type() -> String{"macos".to_owned()}

/* pub fn exit_with_message(message: &str) {
    println!();
    println!("{}", message);
    std::process::exit(0);
} */

pub fn exit_with_error_message(message: &str) {
    println!();
    println!("Error: {}", message);
    std::process::exit(1);
}

pub fn get_exe_dir_path() -> PathBuf {
    let mut path: PathBuf = env::current_exe().unwrap();
    path.pop();
    path
}

pub fn copy_recursively(source: impl AsRef<Path>, destination: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(&destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let filetype = entry.file_type()?;
        if filetype.is_dir() {
            copy_recursively(entry.path(), destination.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), destination.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

pub fn get_install_dir_path() -> PathBuf {
    let mut path: PathBuf = home::home_dir().unwrap();
    path.push(".nesmap");
    path
}

pub fn check_cli_package() -> bool {
    let mut path: PathBuf = get_exe_dir_path();
    path.push(define::PACKAGE_DIR_NAME);
    path.push(define::PACKAGE_NAME_NESMAP);
    println!("{:?}", path);
    path.exists()
}

pub fn check_gui_package() -> bool {
    let mut path: PathBuf = get_exe_dir_path();
    path.push(define::PACKAGE_DIR_NAME);
    path.push(define::PACKAGE_NAME_NESMAP_DESKTOP);
    println!("{:?}", path);
    path.exists()
}
