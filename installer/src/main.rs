#[macro_use]
extern crate clap;

mod define;
mod sys;
mod install;

use std::env;
use clap::{Command, AppSettings, Arg, App};

fn main() {
    show_app_desc();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        install::intaractive_install();
    }
    let app = get_app_settings();
    let matches = app.get_matches();
    if matches.contains_id("check") {
        if install::check_installation() {
            println!("Installation is complete.");
        }else {
            println!("Installation is incomplete. Please check the above messages.");
        }
    }else if matches.contains_id("install") {
        install::install();
    }else if matches.contains_id("update") {
    
    }else if matches.contains_id("uninstall") {
        
    }else{
        install::intaractive_install();
    }
}

fn get_app_settings<'a>() -> Command<'a> {
    let app: App = Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(Arg::new("check")
            .help("Check installation and dependencies")
            .short('c')
            .long("check")
        )
        .arg(Arg::new("install")
            .help("Install applications and dependencies")
            .short('i')
            .long("install")
        )
        .arg(Arg::new("update")
            .help("Update applications and database")
            .short('u')
            .long("update")
        )
        .arg(Arg::new("uninstall")
            .help("Uninstall applications")
            .short('d')
            .long("uninstall")
        )
        .arg(Arg::new("offline")
            .help("Offline mode")
            .short('o')
            .long("offline")
        )
        .arg(Arg::new("online")
            .help("Online mode")
            .short('n')
            .long("online")
        )
        .arg(Arg::new("auto")
            .help("Skip prompt")
            .short('a')
            .long("auto")
        )
        .setting(AppSettings::DeriveDisplayOrder)
        ;
        app
}

fn show_app_desc() {
    println!("{} {} ({}) {}", crate_name!(), crate_version!(), define::CRATE_UPDATE_DATE, sys::get_os_type());
    println!("{}", crate_description!());
    println!("{}", crate_authors!());
    println!("{}", define::CRATE_REPOSITORY);
    println!();
    println!("'{} --help' for more information.", crate_name!());
    println!();
}
