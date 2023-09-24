pub(crate) mod define;
pub(crate) mod sys;
pub mod npcap;

use inquire::Confirm;

/// Check and resolve dependencies
pub fn resolve_dependencies(interactive: bool) -> bool {
    // Check if npcap is installed
    if !npcap::is_npcap_installed() {
        let ans: bool = if interactive { 
            Confirm::new("Npcap is not installed, would you like to install it ?")
            .prompt()
            .unwrap()
        }else{
            true
        };
        if ans == false {
            println!("Exiting...");
            return false;
        }
        println!("Installing Npcap...");
        match npcap::install_npcap() {
            Ok(_) => println!("Npcap installed successfully !"),
            Err(e) => println!("{}", e),
        }
    } else {
        println!("Npcap is already installed !");
    }
    // Check if npcap sdk is installed
    if !npcap::is_npcap_sdk_installed() {
        let ans: bool = if interactive { 
            Confirm::new("Npcap SDK is not installed, would you like to install it ?")
            .prompt()
            .unwrap()
        } else { 
            true 
        };
        if ans == false {
            println!("Exiting...");
            return false;
        }
        println!("Installing Npcap SDK...");
        match npcap::install_npcap_sdk() {
            Ok(_) => println!("Npcap SDK installed successfully !"),
            Err(e) => println!("{}", e),
        }
    } else {
        println!("Npcap SDK is already installed !");
    }
    true
}