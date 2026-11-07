//! Shield core: everything that is the same on every OS. OS services come from `shield_platform`;
//! this crate contains no `cfg(windows)` / `cfg(unix)` product code (a few tests that need an
//! OS-specific way to provoke an error are gated).

pub mod ads;
pub mod archive;
pub mod buildinfo;
pub mod compress;
pub mod container;
pub mod crypto;
pub mod engine;
pub mod entropy;
pub mod format;
pub mod harden;
pub mod help;
pub mod i18n;
pub mod job;
pub mod keyfile;
pub mod lang;
pub mod lock;
pub mod manifest;
pub mod outname;
pub mod password;
pub mod progress;
pub mod rekey;
pub mod sectemp;
pub mod settings;
pub mod settings_auth;
pub mod sigverify;
pub mod spool;
pub mod staging;
pub mod sysinfo;
pub mod ui_fmt;
pub mod ui_prefs;
pub mod update;
pub mod wipe;

#[cfg(test)]
mod fuzz_tests;
#[cfg(test)]
mod cross_os_tests;
#[cfg(test)]
mod release_tests;

pub use shield_platform as platform;
