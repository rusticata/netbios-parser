//! [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
//! [![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
//! [![Crates.io Version](https://img.shields.io/crates/v/netbios-parser.svg)](https://crates.io/crates/netbios-parser)
//! [![docs.rs](https://docs.rs/netbios-parser/badge.svg)](https://docs.rs/netbios-parser)
//! [![Github CI](https://github.com/rusticata/netbios-parser/workflows/Continuous%20integration/badge.svg)](https://github.com/rusticata/netbios-parser/actions)
//! [![Minimum rustc version](https://img.shields.io/badge/rustc-1.44.0+-lightgray.svg)](#rust-version-requirements)
//!
//! NetBIOS parser
//!
//! This crate contains parsers for the NetBIOS ([rfc1002]) network format, in pure Rust.
//!
//! Currently only NBSS parsing is implemented
//!
//! The code is available on [Github](https://github.com/rusticata/pcap-parser)
//! and is part of the [Rusticata](https://github.com/rusticata) project.
//!
//! [rfc1002]: https://www.ietf.org/rfc/rfc1002.txt
#![deny(/*missing_docs,*/
    unstable_features,
    unused_import_braces,
    unused_qualifications,
    unreachable_pub)]
#![forbid(unsafe_code)]
#![warn(
/*missing_docs,
rust_2018_idioms,*/
missing_debug_implementations,
)]
// pragmas for doc
#![deny(broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(test(
no_crate_inject,
attr(deny(warnings/*, rust_2018_idioms*/), allow(dead_code, unused_variables))
))]
// clippy
#![allow(clippy::upper_case_acronyms)]

mod error;
mod nbss_parser;
mod nbss_types;

pub use error::*;
pub use nbss_parser::*;
pub use nbss_types::*;

pub use dns_parser;
pub use nom_derive::nom;
