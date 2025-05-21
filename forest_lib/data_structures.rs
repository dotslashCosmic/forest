// Author: dotslashCosmic

use zeroize::Zeroize;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct DataShard {
    pub data: Vec<u8>,
    pub shard_index: i32,
    pub integrity_hash: Vec<u8>, // Hash of the encrypted 'data' vector
}

impl DataShard {
    pub fn new(index: i32, shard_data: Vec<u8>, hash: Vec<u8>) -> Self {
        DataShard {
            data: shard_data,
            shard_index: index,
            integrity_hash: hash,
        }
    }

    pub fn empty() -> Self {
        DataShard {
            data: Vec::new(),
            shard_index: -1,
            integrity_hash: Vec::new(),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.shard_index != -1 && !self.data.is_empty()
        // TODO double verify integrity_hash is non-empty if expected.
    }
}

#[derive(Debug, Clone, Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub struct EncryptedKeyMaterial {
    pub encrypted_dek: Vec<u8>, // Encrypted Data Encryption Key 
    pub encryption_iv: Vec<u8>, // IV/Nonce for encrypting the DEK
    pub salt: Vec<u8>, // Salt used for KDF if KEK was derived from a password to encrypt this DEK
    pub usb_key_uuid: String, // UsbKey UUID it's tied to
}

impl EncryptedKeyMaterial {
    pub fn new(
        encrypted_dek: Vec<u8>,
        encryption_iv: Vec<u8>,
        salt: Vec<u8>,
        usb_key_uuid: String,
    ) -> Self {
        EncryptedKeyMaterial {
            encrypted_dek,
            encryption_iv,
            salt,
            usb_key_uuid,
        }
    }

    pub fn empty() -> Self {
        EncryptedKeyMaterial {
            encrypted_dek: Vec::new(),
            encryption_iv: Vec::new(),
            salt: Vec::new(),
            usb_key_uuid: String::new(),
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.encrypted_dek.is_empty() 
        && !self.encryption_iv.is_empty() 
        && !self.usb_key_uuid.is_empty()
        // TODO salt may be empty if KEK isnt PW derived for DEK encryption, or if KEK is stored without pw derivation
    }
}
