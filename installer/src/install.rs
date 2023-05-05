use std::{io, fs};
use std::path::{PathBuf};
use std::io::Write;
use crate::{sys, define};

pub fn create_default_install_dir() {
    // Create $HOME/.nesmap
    let mut path: PathBuf = home::home_dir().unwrap();
    path.push(".nesmap");
    if !path.exists() {
        println!("Create install directory: {}", path.display());
        match fs::create_dir(path) {
            Ok(_) => {},
            Err(e) => {
                sys::exit_with_error_message(e.to_string().as_str());
            }
        }
    }
}

pub fn copy_cli_package() {
    let mut src_path: PathBuf = sys::get_exe_dir_path();
    src_path.push(define::PACKAGE_DIR_NAME);
    src_path.push(define::PACKAGE_NAME_NESMAP);
    if sys::get_os_type() == "macos" {
        src_path.push("Contents");
        src_path.push("MacOS");
    }
    src_path.push(define::APP_NAME_NESMAP);

    let mut dst_path: PathBuf = sys::get_install_dir_path();
    dst_path.push(define::APP_NAME_NESMAP);
    match fs::copy(src_path, dst_path) {
        Ok(_) => {},
        Err(e) => {
            sys::exit_with_error_message(e.to_string().as_str());
        }
    }
}

pub fn copy_gui_package() {
    let mut src_path: PathBuf = sys::get_exe_dir_path();
    src_path.push(define::PACKAGE_DIR_NAME);
    src_path.push(define::PACKAGE_NAME_NESMAP_DESKTOP);
    let mut dst_path: PathBuf = sys::get_install_dir_path();
    dst_path.push(define::PACKAGE_NAME_NESMAP_DESKTOP);
    match sys::copy_recursively(src_path, dst_path) {
        Ok(_) => {},
        Err(e) => {
            sys::exit_with_error_message(e.to_string().as_str());
        }
    }
}

pub fn copy_db() {
    let mut src_path: PathBuf = sys::get_exe_dir_path();
    src_path.push(define::PACKAGE_DIR_NAME);
    src_path.push(define::PRESOURCE_DIR_NAME);
    src_path.push(define::DB_NAME);
    let mut dst_path: PathBuf = sys::get_install_dir_path();
    dst_path.push(define::DB_NAME);
    match fs::copy(src_path, dst_path) {
        Ok(_) => {},
        Err(e) => {
            sys::exit_with_error_message(e.to_string().as_str());
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn add_path() {
    // Select current shell and rc file
    let rc_path: PathBuf = sys::get_rc_file_path();
    let mut file = match fs::OpenOptions::new().append(true).open(rc_path.clone()) {
        Ok(file) => file,
        Err(e) => {
            return sys::exit_with_error_message(e.to_string().as_str());
        }
    };
    let install_path: PathBuf = sys::get_install_dir_path();
    let mut path_str = String::from("export PATH=\"$PATH:");
    path_str.push_str(install_path.to_str().unwrap());
    path_str.push_str("\"\n");
    match file.write_all(path_str.as_bytes()) {
        Ok(_) => {
            sys::write_console_log(format!("Path added to {}", rc_path.display()).as_str());
            println!("Please restart your terminal or run `source {}`", rc_path.display());
        },
        Err(e) => {
            sys::exit_with_error_message(e.to_string().as_str());
        }
    }
}

#[cfg(target_os = "windows")]
pub fn add_path(){

}

/* #[cfg(not(target_os = "windows"))]
pub fn remove_path() {

}

#[cfg(target_os = "windows")]
pub fn remove_path() {

} */

pub fn check_installation() -> bool {
    println!("Checking installation...");
    let mut path: PathBuf = sys::get_install_dir_path();
    path.push(define::APP_NAME_NESMAP);
    if path.exists() {
        sys::write_console_log("Package `nesmap` found.");
    }else{
        sys::write_console_log("Package `nesmap` not found.");
        return false;
    }
    path.pop();
    path.push(define::PACKAGE_NAME_NESMAP_DESKTOP);
    if path.exists() {
        sys::write_console_log("Package `nesmap-desktop` found.");
    }else {
        sys::write_console_log("Package `nesmap-desktop` not found.");
        return false;
    }
    path.pop();
    path.push(define::DB_NAME);
    if path.exists() {
        sys::write_console_log("Database found.");
    }else {
        sys::write_console_log("Database not found.");
        return false;
    }
    if sys::check_app_env_path() {
        sys::write_console_log("Path found.");
    }else {
        sys::write_console_log("Path not found.");
        return false;
    }
    return true;
}

pub fn install_offline() {
    sys::write_console_log("Checking packages...");
    if !sys::check_cli_package() {
        sys::exit_with_error_message("package `nesmap` not found. Exit.");
    }
    if !sys::check_gui_package() {
        sys::exit_with_error_message("package `nesmap-desktop` not found. Exit.");
    }
    sys::write_console_log("Installing nesmap-database ...");
    copy_db();
    sys::write_console_log("Installing nesmap ...");
    copy_cli_package();
    sys::write_console_log("Installing nesmap-desktop ...");
    copy_gui_package();
    if !sys::check_app_env_path() {
        sys::write_console_log("Adding path ...");
        add_path();
    }
}

pub fn install_online() {

}

pub fn install() {
    println!("Start installation of nesmap.");

    println!("Installing nesmap packages...");
    create_default_install_dir();
    install_offline();
    println!("Installation complete.");
}

pub fn intaractive_install() {
    println!("Start installation of nesmap.");
    print!("Press any key to continue...");
    io::stdout().flush().unwrap();
    let mut user_input = String::new();
    match io::stdin().read_line(&mut user_input){
        Ok(_) => {},
        Err(e) => {
            sys::exit_with_error_message(e.to_string().as_str());
        }
    }
    user_input.clear();
    println!();
    let mut online: bool = false;
    print!("Do you want to install online? [y/N]: ");
    io::stdout().flush().unwrap();
    match io::stdin().read_line(&mut user_input){
        Ok(_) => {},
        Err(e) => {
            sys::exit_with_error_message(e.to_string().as_str());
        }
    }
    println!("Installing nesmap packages...");
    create_default_install_dir();
    if user_input.to_lowercase().as_str() == "y" {
        online = true;
    }
    if online {
        install_online();
    } else {
        install_offline();
    }
    println!("Installation complete.");
    print!("Press any key to exit...");
    io::stdout().flush().unwrap();
    match io::stdin().read_line(&mut user_input){
        Ok(_) => {},
        Err(e) => {
            sys::exit_with_error_message(e.to_string().as_str());
        }
    }
    println!();
}
