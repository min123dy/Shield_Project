//! String tables. `*_core`: engine messages, errors, stages. `*_ui`: screens. `help_*`: usage texts.
//! Every table of one area must have exactly the same keys in every language (tested).

pub mod en_core;
pub mod en_ui;
pub mod help_en;
pub mod help_ko;
pub mod ko_core;
pub mod ko_ui;
