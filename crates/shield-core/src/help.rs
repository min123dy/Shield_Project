//! Texts for the help tabs (one per window) and the algorithms tab, per language
//! (lang/help_ko.rs, lang/help_en.rs). Only describe what is implemented; limits are stated plainly.

use crate::i18n::{lang, Lang};
use crate::lang::{help_en as en, help_ko as ko};

pub type Sections = &'static [(&'static str, &'static [&'static str])];
pub type Rows = &'static [(&'static str, &'static str)];

pub fn enc_usage() -> Sections {
    if lang() == Lang::En { en::ENC_USAGE } else { ko::ENC_USAGE }
}
pub fn mgr_usage() -> Sections {
    if lang() == Lang::En { en::MGR_USAGE } else { ko::MGR_USAGE }
}
pub fn algo_rows() -> Rows {
    if lang() == Lang::En { en::ALGO_ROWS } else { ko::ALGO_ROWS }
}
pub fn algo_notes() -> &'static [&'static str] {
    if lang() == Lang::En { en::ALGO_NOTES } else { ko::ALGO_NOTES }
}
