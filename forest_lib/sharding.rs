// Author: dotslashCosmic
use crate::{
    config,
    crypto,
    data_structures::DataShard,
    main_storage::MainStorage, // MainStorage is used for storing/retrieving shards and manifests
    usb_key::UsbKey, // UsbKey is used for retrieving the USB shard
    secure_utils, // For constant-time comparison
};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write, Seek, SeekFrom},
    path::{Path, PathBuf}, // PathBuf is needed for constructing file paths
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileManifest {
    pub original_filename: String,
    pub original_file_size: u64,
    pub total_shards: usize,
    pub shard_info: Vec<ShardInfo>,
    pub file_id: String, 
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ShardInfo {
    pub shard_index: i32, // 0 to total_shards - 1
    pub nonce: Vec<u8>, // Nonce used for encrypting this shard's data
    pub encrypted_data_hash: Vec<u8>, // Hash of the ciphertext of this shard
    pub storage_location: ShardStorageLocation,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ShardStorageLocation {
    UsbKey,
    MainStorage { index_in_main_storage: i32 }, // MainStorage stores shards by index
}

pub fn shard_file(
    file_path: &Path,
    main_storage_dek: &[u8],
    file_id: &str, // Uuid::new_v4().to_string()
) -> Result<(FileManifest, Vec<DataShard>)> {
    if !file_path.exists() || !file_path.is_file() {
        return Err(anyhow!("File not found or is not a regular file: {:?}", file_path));
    }
    if main_storage_dek.len() != config::DEK_LENGTH {
        return Err(anyhow!("Invalid MainStorage DEK length. Expected {}, got {}", config::DEK_LENGTH, main_storage_dek.len()));
    }

    let mut file = File::open(file_path)
        .with_context(|| format!("Failed to open file for sharding: {:?}", file_path))?;
    let original_file_size = file.metadata()?.len();
    let original_filename = file_path.file_name().unwrap_or_default().to_string_lossy().into_owned();

    let mut shards_data_for_storage: Vec<DataShard> = Vec::new();
    let mut shard_metadata_for_manifest: Vec<ShardInfo> = Vec::new();
    
    let mut buffer = vec![0u8; config::MAX_SHARD_SIZE_BYTES];
    let mut current_shard_index = 0;
    let mut bytes_remaining = original_file_size;

    println!(
        "Sharding file: '{}' ({} bytes), Max shard size: {} bytes",
        original_filename, original_file_size, config::MAX_SHARD_SIZE_BYTES
    );

    if original_file_size == 0 {
        let plaintext_shard_data = &[];
        let (encrypted_data, nonce) = crypto::encrypt_xchacha20_poly1305(plaintext_shard_data, main_storage_dek, None)
            .with_context("Failed to encrypt empty shard for empty file")?;
        let encrypted_data_hash = crypto::hash_sha3_512(&encrypted_data)
            .with_context("Failed to hash empty encrypted shard")?;

        let storage_location = if config::USB_KEY_SHARD_INDEX == 0 {
            ShardStorageLocation::UsbKey
        } else {
            ShardStorageLocation::MainStorage { index_in_main_storage: 0 }
        };

        shard_metadata_for_manifest.push(ShardInfo {
            shard_index: 0,
            nonce,
            encrypted_data_hash: encrypted_data_hash.clone(),
            storage_location,
        });
        shards_data_for_storage.push(DataShard {
            data: encrypted_data,
            shard_index: 0,
            integrity_hash: encrypted_data_hash,
        });
        current_shard_index = 1;
        println!("Handled empty file: created 1 empty shard.");
    } else {
        loop {
            let bytes_to_read = std::cmp::min(buffer.len() as u64, bytes_remaining) as usize;
            if bytes_to_read == 0 {
                break;
            }

            file.read_exact(&mut buffer[..bytes_to_read])
                .with_context(|| format!("Failed to read chunk for shard {} from file", current_shard_index))?;
            
            let plaintext_shard_data = &buffer[..bytes_to_read];

            let (encrypted_data, nonce) = crypto::encrypt_xchacha20_poly1305(plaintext_shard_data, main_storage_dek, None)
                .with_context(|| format!("Failed to encrypt shard {}", current_shard_index))?;

            let encrypted_data_hash = crypto::hash_sha3_512(&encrypted_data)
                .with_context(|| format!("Failed to hash encrypted data for shard {}", current_shard_index))?;

            let storage_location = if current_shard_index == config::USB_KEY_SHARD_INDEX as i32 {
                ShardStorageLocation::UsbKey
            } else {
                // TODO For MainStorage, index might be different from current_shard_index if USB shard is skipped
                // or same if MainStorage handles non-contiguous indices
                ShardStorageLocation::MainStorage { index_in_main_storage: current_shard_index }
            };

            shard_metadata_for_manifest.push(ShardInfo {
                shard_index: current_shard_index,
                nonce: nonce.clone(), // Clone nonce for manifest
                encrypted_data_hash: encrypted_data_hash.clone(), // Clone hash for manifest
                storage_location,
            });

            shards_data_for_storage.push(DataShard {
                data: encrypted_data, // Store the actual encrypted data
                shard_index: current_shard_index,
                integrity_hash: encrypted_data_hash, // Store the hash of the encrypted data
            });
            
            println!("Created shard {}: Plaintext size: {}, Encrypted size: {}", current_shard_index, plaintext_shard_data.len(), shards_data_for_storage.last().unwrap().data.len());

            bytes_remaining -= bytes_to_read as u64;
            current_shard_index += 1;

            if bytes_remaining == 0 {
                break;
            }
        }
    }
    
    let manifest = FileManifest {
        original_filename,
        original_file_size,
        total_shards: current_shard_index as usize, // number of shards created
        shard_info: shard_metadata_for_manifest,
        file_id: file_id.to_string(),
    };

    Ok((manifest, shards_data_for_storage))
}

pub fn reconstruct_file(
    manifest: &FileManifest,
    main_storage_dek: &[u8],
    output_path: &Path,
    usb_key: &mut UsbKey, // Needs to be mutable if retrieve_usb_shard requires for auth state
    main_storage: &MainStorage, // Assuming MainStorage::retrieve_shard takes &self
) -> Result<()> {
    if main_storage_dek.len() != config::DEK_LENGTH {
        return Err(anyhow!("Invalid MainStorage DEK length."));
    }
    if manifest.shard_info.len() != manifest.total_shards {
        return Err(anyhow!("Manifest inconsistency: shard_info length does not match total_shards."));
    }

    let mut output_file = File::create(output_path)
        .with_context(|| format!("Failed to create output file for reconstruction: {:?}", output_path))?;

    let mut total_bytes_written: u64 = 0;
    println!("Reconstructing file: '{}', expected size: {}, total shards: {}", manifest.original_filename, manifest.original_file_size, manifest.total_shards);


    for i in 0..manifest.total_shards {
        let info = manifest.shard_info.iter().find(|si| si.shard_index == i as i32)
            .ok_or_else(|| anyhow!("Missing shard info in manifest for logical shard index {}", i))?;

        // Retrieve the encrypted DataShard
        let retrieved_shard_for_decryption: DataShard = match &info.storage_location {
            ShardStorageLocation::UsbKey => {
                if info.shard_index != config::USB_KEY_SHARD_INDEX as i32 {
                    return Err(anyhow!("Manifest indicates USB shard for index {}, but USB key is configured for index {}.", info.shard_index, config::USB_KEY_SHARD_INDEX));
                }
                usb_key.retrieve_usb_shard().with_context(|| format!("Failed to retrieve shard {} (USB part) from UsbKey", info.shard_index))?
            }
            ShardStorageLocation::MainStorage { index_in_main_storage } => {
                main_storage.retrieve_shard(*index_in_main_storage) 
                    .with_context(|| format!("Failed to retrieve shard {} (MainStorage part, physical index {}) from MainStorage", info.shard_index, index_in_main_storage))?
            }
        };

        if !secure_utils::constant_time_compare(&retrieved_shard_for_decryption.integrity_hash, &info.encrypted_data_hash) {
            return Err(anyhow!(
                "Integrity check failed for retrieved shard {} (index {}). Manifest hash: {:?}, Shard hash: {:?}",
                info.shard_index, retrieved_shard_for_decryption.shard_index, info.encrypted_data_hash, retrieved_shard_for_decryption.integrity_hash
            ));
        }

        let decrypted_data = crypto::decrypt_xchacha20_poly1305(
            &retrieved_shard_for_decryption.data,
            main_storage_dek,
            &info.nonce,
            None,
        ).with_context(|| format!("Failed to decrypt shard {}", info.shard_index))?;

        output_file.write_all(&decrypted_data)
            .with_context(|| format!("Failed to write decrypted data for shard {} to output file", info.shard_index))?;
        
        total_bytes_written += decrypted_data.len() as u64;
        println!("Processed shard {}: Decrypted size: {}", info.shard_index, decrypted_data.len());
    }

    if total_bytes_written != manifest.original_file_size {
        output_file.set_len(manifest.original_file_size).with_context(|| "Failed to set final file length")?;
        eprintln!(
            "Warning: Reconstructed file size mismatch. Expected {}, wrote {}. File truncated/adjusted.",
            manifest.original_file_size, total_bytes_written
        );
    }
    
    output_file.sync_all().with_context("Failed to sync reconstructed file to disk")?;
    println!("File reconstruction successful: {:?}", output_path);
    Ok(())
}

pub fn store_manifest(main_storage: &MainStorage, manifest: &FileManifest, manifest_dek: &[u8]) -> Result<()> {
    let serialized_manifest = bincode::serialize(manifest)
        .with_context(|| "Failed to serialize file manifest")?;

    // dedicated manifest_dek is good, or  main_storage_dek if policy allows
    let (encrypted_manifest_data, nonce) = crypto::encrypt_xchacha20_poly1305(&serialized_manifest, manifest_dek, None)
        .with_context(|| "Failed to encrypt file manifest")?;

    let mut data_to_store = nonce;
    data_to_store.extend(encrypted_manifest_data);

    main_storage.store_manifest_data(&manifest.file_id, &data_to_store)
        .with_context(|| "Failed to store encrypted manifest")
}

pub fn retrieve_manifest(main_storage: &MainStorage, file_id: &str, manifest_dek: &[u8]) -> Result<FileManifest> {
    let stored_data = main_storage.retrieve_manifest_data(file_id)
        .with_context(|| format!("Failed to retrieve encrypted manifest for file_id: {}", file_id))?
        .ok_or_else(|| anyhow!("Manifest file not found for file_id: {}", file_id))?;

    if stored_data.len() < crypto::XNONCE_LEN {
        return Err(anyhow!("Retrieved manifest data too short to contain nonce."));
    }

    let (nonce, encrypted_manifest_data) = stored_data.split_at(crypto::XNONCE_LEN);
    
    let serialized_manifest = crypto::decrypt_xchacha20_poly1305(encrypted_manifest_data, manifest_dek, nonce, None)
        .with_context(|| "Failed to decrypt file manifest")?;
        
    bincode::deserialize(&serialized_manifest)
        .with_context(|| "Failed to deserialize file manifest")
}
