#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! `shield-gui` - the windowed launcher (no console window).
//!   shield-gui                          start screen from Settings
//!   shield-gui --encrypt-multi <items>  encryption window (Explorer starts one process per item;
//!                                       they are gathered into one window, see shield_core::spool)
//!   shield-gui --decrypt <file.shd>     decryption tab
//!   shield-gui --manager [<path>]       file manager window
//!   shield-gui --open <file.shd>        file manager window, container unlock screen
//!   shield-gui --settings               settings

use shield_gui::{parse_args, run, Start};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Elevated TRIM helper started through UAC: must exit before any window is created.
    if let Some(code) = shield_platform::sys::elevated_helper(&args) {
        std::process::exit(code);
    }
    let start = match parse_args(&args) {
        Start::Encrypt(items) if args.first().map(String::as_str) == Some("--encrypt-multi") => {
            match shield_gui::spool::gather(&shield_gui::settings::data_dir(), &items) {
                Ok(shield_gui::spool::Role::Done) => return,
                Ok(shield_gui::spool::Role::Lead(all)) => Start::Encrypt(all),
                Err(_) => Start::Encrypt(items),
            }
        }
        s => s,
    };
    std::process::exit(run(start));
}
