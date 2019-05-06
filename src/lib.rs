//! The Routinator Library
//!
//! This crate contains all the moving parts of the Routinator. The
//! application itself, via `main.rs` is only a very tiny frontend.

// Clippy due to multi-versioning
#![allow(renamed_and_removed_lints)]

// Clippy for 1.30.
#![allow(unknown_lints)]
#![allow(needless_pass_by_value)]
#![allow(map_clone)]

extern crate bytes;
extern crate chrono;
#[macro_use] extern crate clap;
#[cfg(unix)] extern crate daemonize;
#[macro_use] extern crate derive_more;
extern crate dirs;
extern crate fern;
#[macro_use] extern crate futures;
extern crate futures_cpupool;
extern crate httparse;
extern crate json;
#[macro_use] extern crate log;
extern crate num_cpus;
extern crate rand;
extern crate reqwest;
extern crate ring;
extern crate rpki;
#[macro_use] extern crate serde;
extern crate serde_json;
extern crate slab;
#[cfg(unix)] extern crate syslog;
extern crate tempfile;
extern crate tokio;
extern crate tokio_process;
extern crate toml;
extern crate uuid;
#[macro_use] extern crate unwrap;

pub use self::config::Config;
pub use self::operation::{Error, Operation};

pub mod config;
pub mod metrics;
pub mod monitor;
pub mod operation;
pub mod origins;
pub mod output;
pub mod repository;
pub mod rrdp;
pub mod rtr;
pub mod slurm;

