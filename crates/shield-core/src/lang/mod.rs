//! String tables. `*_core`: engine messages, errors, stages. `*_ui`: GUI screens. `*_v3`: 3.0
//! additions (updates, signatures, settings password, shredding policy). `*_cli`: console.
//! `help_*`: usage texts. `*_sd`: secure delete (3.1.0 final).
//! Every table of one area must have exactly the same keys in every language (tested).

pub mod en_cli;
pub mod en_core;
pub mod en_sd;
pub mod en_ui;
pub mod en_v3;
pub mod help_en;
pub mod help_ko;
pub mod ko_cli;
pub mod ko_core;
pub mod ko_sd;
pub mod ko_ui;
pub mod ko_v3;
