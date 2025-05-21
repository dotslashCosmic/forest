// Author: dotslashCosmic
pub mod config;
pub mod data_structures;
pub mod secure_utils;
pub mod crypto;
pub mod main_storage;
pub mod usb_key;
pub mod sharding;

pub use usb_key::{AuthAction, AuthFailure, AuthenticationOutcome};
pub use data_structures::DataShard;

use thiserror::Error;
#[derive(Error, Debug)]
pub enum ForestError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Cryptography error: {0}")]
    Crypto(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}