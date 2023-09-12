pub mod define;
pub mod sys;
pub mod npcap;

use inquire::Confirm;

pub fn check_dependencies() -> bool {
    // check if npcap is installed
    if !npcap::is_npcap_installed() {
        let ans: bool = Confirm::new("Npcap is not installed, would you like to install it ?")
        .prompt()
        .unwrap();
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
    true
}
