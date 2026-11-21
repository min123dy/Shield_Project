#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! `shield-gui` - the windowed launcher (no console window).
//!   shield-gui                          start screen from Settings
//!   shield-gui --encrypt-multi <items>  encryption window (Explorer starts one process per item;
//!                                       they are gathered into one window, see shield_core::spool)
//!   shield-gui --decrypt <file.shd>     decryption tab
//!   shield-gui --manager [<path>]       file manager window
//!   shield-gui --open <file.shd>        file manager window, container unlock screen
//!   shield-gui --settings               settings
//!   shield-gui --wipe [--] <items>      secure delete tab with these items (gathered like
//!                                       --encrypt-multi; scanned and confirmed in the window)

use shield_gui::{parse_args, run, Start};

fn main() {
    // args_os (3.1.0 final, 4-1): std::env::args panics on an argument that is not UTF-8, and a
    // Linux file manager passes such names. It becomes "", which every launch path reports as
    // unusable instead of turning it into another (possibly existing) name.
    let args: Vec<String> = std::env::args_os().skip(1).map(|a| a.into_string().unwrap_or_default()).collect();
    // Elevated TRIM helper started through UAC: must exit before any window is created.
    if let Some(code) = shield_platform::sys::elevated_helper(&args) {
        std::process::exit(code);
    }
    // Elevated update helper (3.1.0 #1; Windows `--install-update <4 files>`): copies, verifies and
    // installs before any window exists. It refuses to run unless elevated.
    if args.first().map(String::as_str) == Some(shield_platform::sys::UPDATE_HELPER_ARG) {
        std::process::exit(shield_core::update::helper_main(&args[1..]));
    }
    use shield_gui::spool::{gather, Kind, Role};
    // one process per selected item (Explorer): the first one gathers them (core `spool`); items
    // are made absolute first (review F: relative names from file managers)
    let gathered = |kind: Kind, items: Vec<std::path::PathBuf>| {
        let (items, bad) = shield_gui::absolute_items(&items);
        match shield_gui::settings::data_dir().map_err(std::io::Error::other).and_then(|d| gather(&d, kind, &items)) {
            Ok(Role::Done) => None,
            Ok(Role::Lead { items, dropped }) => Some((items, dropped + bad)),
            Err(_) => Some((items, bad)),
        }
    };
    let start = match parse_args(&args) {
        Start::Encrypt { items, .. } if args.first().map(String::as_str) == Some("--encrypt-multi") => match gathered(Kind::Encrypt, items) {
            None => return,
            Some((items, dropped)) => Start::Encrypt { items, dropped },
        },
        Start::Wipe { items, .. } => match gathered(Kind::Wipe, items) {
            None => return,
            Some((items, dropped)) => Start::Wipe { items, dropped },
        },
        s => s,
    };
    std::process::exit(run(start));
}
