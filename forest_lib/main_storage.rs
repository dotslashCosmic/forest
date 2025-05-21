// Author: dotslashCosmic
use crate::config;
use crate::data_structures::{DataShard, EncryptedKeyMaterial};
/use crate::secure_utils;
use crate::crypto;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize}; // Required if MainStorage becomes serializable, or local structs
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::cmp::max;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq /*, Zeroize if it contains sensitive data */)]
pub enum StorageType {
    Local,
    S3, // Placeholder
    GoogleDrive, // Placeholder
    Dropbox, // Placeholder
    Unknown,
}

#[derive(Debug, Clone /*, Zeroize, ZeroizeOnDrop if it contains sensitive data */)]
pub struct CloudConfig {
    pub provider: StorageType,
    pub s3_bucket_name: String,
    pub s3_region: String,
    // WARN store api keys in configuration file with strict perms
    pub api_key: String,
    pub oauth_client_secret: String,
    pub oauth_access_token: String,
    pub oauth_refresh_token: String,
    pub gdrive_root_folder_id: String,
    pub dropbox_app_key: String,
    pub dropbox_app_secret: String,
}

impl CloudConfig {
    pub fn new(provider: StorageType) -> Self {
        CloudConfig {
            provider,
            s3_bucket_name: String::new(),
            s3_region: String::new(),
            api_key: String::new(),
            oauth_client_secret: String::new(),
            oauth_access_token: String::new(),
            oauth_refresh_token: String::new(),
            gdrive_root_folder_id: String::new(),
            dropbox_app_key: String::new(),
            dropbox_app_secret: String::new(),
        }
    }
}

pub trait CloudStorageClient: Send + Sync {
    fn initialize_client(&mut self, config: &CloudConfig) -> Result<()>;
    fn store_data(&self, object_key: &str, data: &[u8]) -> Result<()>;
    fn retrieve_data(&self, object_key: &str) -> Result<Vec<u8>>;
    fn delete_data(&self, object_key: &str) -> Result<()>;
    fn secure_delete_data(&self, object_key: &str) -> Result<()>;
    fn object_exists(&self, object_key: &str) -> Result<bool>;
    fn list_objects(&self, prefix: &str) -> Result<Vec<String>>;
}

pub struct MainStorage {
    storage_location_identifier: String,
    storage_type: StorageType,
    cloud_config: Option<CloudConfig>, // only if storage_type is cloud
    is_initialized: bool,
    cloud_client: Option<Box<dyn CloudStorageClient>>, // TODO implement actual cloud clients
}

impl MainStorage {
    pub fn new(location_identifier: String, storage_type: StorageType, cloud_config: Option<CloudConfig>) -> Self {
        MainStorage {
            storage_location_identifier,
            storage_type,
            cloud_config,
            is_initialized: false,
            cloud_client: None,
        }
    }

    pub fn initialize(&mut self) -> Result<()> {
        if self.is_initialized { return Ok(()); }
        if self.storage_location_identifier.is_empty() {
            return Err(anyhow!("Storage location identifier cannot be empty."));
        }

        match self.storage_type {
            StorageType::Local => {
                let storage_path = PathBuf::from(&self.storage_location_identifier);
                if !storage_path.exists() {
                    fs::create_dir_all(&storage_path).with_context(|| format!("Failed to create main storage directory: {:?}", storage_path))?;
                } else if !storage_path.is_dir() {
                    return Err(anyhow!("Storage location exists but is not a directory: {:?}", storage_path));
                }
                // TODO check and enforce dir perms for local storage
            }
            StorageType::S3 | StorageType::GoogleDrive | StorageType::Dropbox => {
                if let Some(config) = &self.cloud_config {
                    // TODO actual cloud client instantiation and initialization.
                    println!("Warning: Cloud client implementation is currently a placeholder. Simulating successful initialization for {:?}.", self.storage_type);
                } else {
                    return Err(anyhow!("Cloud configuration missing for cloud storage type."));
                }
            }
            StorageType::Unknown => return Err(anyhow!("Unknown or unsupported storage type.")),
        }
        self.is_initialized = true;
        Ok(())
    }

    fn get_shard_filepath(&self, shard_index: i32) -> PathBuf {
        PathBuf::from(&self.storage_location_identifier)
            .join(format!("shard_{:05}.dat", shard_index))
    }

    fn get_key_material_filepath(&self) -> PathBuf {
        PathBuf::from(&self.storage_location_identifier).join("key_material.bin")
    }
    
    fn get_manifest_filepath(&self, file_id: &str) -> PathBuf {
        PathBuf::from(&self.storage_location_identifier)
            .join("manifests")
            .join(format!("manifest_{}.bin", file_id))
    }


    pub fn store_shard(&self, shard_to_store: &DataShard) -> Result<()> {
        if !self.is_initialized { return Err(anyhow!("MainStorage not initialized.")); }
        if !shard_to_store.is_valid() { return Err(anyhow!("Invalid DataShard provided for storage.")); }
        
        let serialized_shard = bincode::serialize(shard_to_store)
            .with_context(|| format!("Failed to serialize shard index {}", shard_to_store.shard_index))?;

        match self.storage_type {
            StorageType::Local => {
                let filepath = self.get_shard_filepath(shard_to_store.shard_index);
                Self::write_file_local(&filepath, &serialized_shard)
            }
            _ if self.cloud_client.is_some() => {
                let object_key = format!("shards/shard_{:05}.dat", shard_to_store.shard_index);
                self.cloud_client.as_ref().unwrap().store_data(&object_key, &serialized_shard)
                    .with_context(|| format!("Failed to store cloud shard {} at key '{}'", shard_to_store.shard_index, object_key))
            }
            _ => Err(anyhow!("Cloud client not available for storing shard {}.", shard_to_store.shard_index)),
        }
    }

    pub fn retrieve_shard(&self, shard_index: i32) -> Result<DataShard> {
        if !self.is_initialized { return Err(anyhow!("MainStorage not initialized.")); }
        
        let serialized_shard_bytes = match self.storage_type {
            StorageType::Local => {
                let filepath = self.get_shard_filepath(shard_index);
                Self::read_file_local(&filepath)?
                    .ok_or_else(|| anyhow!("Shard file not found: {:?}", filepath))?
            }
            _ if self.cloud_client.is_some() => {
                let object_key = format!("shards/shard_{:05}.dat", shard_index);
                self.cloud_client.as_ref().unwrap().retrieve_data(&object_key)
                    .with_context(|| format!("Failed to retrieve cloud shard {} from key '{}'", shard_index, object_key))?
            }
            _ => return Err(anyhow!("Cloud client not available for retrieving shard {}.", shard_index)),
        };

        if serialized_shard_bytes.is_empty() {
            return Err(anyhow!("Retrieved shard data is empty for index {}.", shard_index));
        }

        let retrieved_shard: DataShard = bincode::deserialize(&serialized_shard_bytes)
            .with_context(|| format!("Failed to deserialize shard index {}", shard_index))?;
        // TODO Integrity check retrieved_shard.integrity_hash against re-hash of retrieved_shard.data after retrieval and before decryption, in `sharding.rs`, to ensure data wasn't tampered with in transit/storage
        Ok(retrieved_shard)
    }

    pub fn store_encrypted_key_material(&self, key_material: &EncryptedKeyMaterial) -> Result<()> {
        if !self.is_initialized { return Err(anyhow!("MainStorage not initialized.")); }
        if !key_material.is_valid() { return Err(anyhow!("Invalid encrypted key material.")); }

        let serialized_data = bincode::serialize(key_material)
            .with_context(|| "Failed to serialize key material.")?;

        match self.storage_type {
            StorageType::Local => {
                let filepath = self.get_key_material_filepath();
                Self::write_file_local(&filepath, &serialized_data)
            }
            _ if self.cloud_client.is_some() => {
                let object_key = "metadata/key_material.bin";
                self.cloud_client.as_ref().unwrap().store_data(object_key, &serialized_data)
                    .with_context(|| format!("Failed to store cloud key material at key '{}'", object_key))
            }
            _ => Err(anyhow!("Cloud client not available for storing key material.")),
        }
    }

    pub fn retrieve_encrypted_key_material(&self) -> Result<EncryptedKeyMaterial> {
        if !self.is_initialized { return Err(anyhow!("MainStorage not initialized.")); }

        let serialized_data = match self.storage_type {
            StorageType::Local => {
                let filepath = self.get_key_material_filepath();
                Self::read_file_local(&filepath)?
                    .ok_or_else(|| anyhow!("Key material file not found: {:?}", filepath))?
            }
            _ if self.cloud_client.is_some() => {
                let object_key = "metadata/key_material.bin";
                self.cloud_client.as_ref().unwrap().retrieve_data(object_key)
                    .with_context(|| format!("Failed to retrieve cloud key material from key '{}'", object_key))?
            }
            _ => return Err(anyhow!("Cloud client not available for retrieving key material.")),
        };
        
        if serialized_data.is_empty() {
            return Err(anyhow!("Retrieved key material data is empty."));
        }

        bincode::deserialize(&serialized_data)
            .with_context(|| "Failed to deserialize key material.")
    }

    pub fn store_manifest_data(&self, file_id: &str, data: &[u8]) -> Result<()> {
        if !self.is_initialized { return Err(anyhow!("MainStorage not initialized.")); }
        if file_id.is_empty() { return Err(anyhow!("File ID cannot be empty for manifest storage.")); }
        if data.is_empty() { return Err(anyhow!("Manifest data cannot be empty.")); }

        match self.storage_type {
            StorageType::Local => { // bet you won't find this comment lol
                let filepath = self.get_manifest_filepath(file_id);
                Self::write_file_local(&filepath, data)
            }
            _ if self.cloud_client.is_some() => {
                let object_key = format!("manifests/manifest_{}.bin", file_id);
                self.cloud_client.as_ref().unwrap().store_data(&object_key, data)
                    .with_context(|| format!("Failed to store cloud manifest data for file ID '{}' at key '{}'", file_id, object_key))
            }
            _ => Err(anyhow!("Cloud client not available for storing manifest data.")),
        }
    }

    pub fn retrieve_manifest_data(&self, file_id: &str) -> Result<Option<Vec<u8>>> {
        if !self.is_initialized { return Err(anyhow!("MainStorage not initialized.")); }
        if file_id.is_empty() { return Err(anyhow!("File ID cannot be empty for manifest retrieval.")); }

        match self.storage_type {
            StorageType::Local => {
                let filepath = self.get_manifest_filepath(file_id);
                Self::read_file_local(&filepath) // Option<Vec<u8>>
            }
            _ if self.cloud_client.is_some() => {
                let object_key = format!("manifests/manifest_{}.bin", file_id);
                // TODO ensure object_exists is called first if retrieve_data doesn't return Option
                match self.cloud_client.as_ref().unwrap().retrieve_data(&object_key) {
                    Ok(data) => Ok(Some(data)),
                    Err(e) => {
                        // TODO parse error type to distinguish "not found" from others
                        eprintln!("Cloud retrieve_manifest_data for {} failed: {}. Assuming not found for now.", file_id, e);
                        Ok(None) 
                    }
                }
            }
            _ => Err(anyhow!("Cloud client not available for retrieving manifest data.")),
        }
    }

    pub fn secure_erase_all_data(&mut self) -> Result<()> {
        if !self.is_initialized { return Err(anyhow!("MainStorage not initialized.")); }
        println!("Info: Starting secure erase of all data in {}", self.storage_location_identifier);
        self.erase_all_shards_keys_and_manifests()
    }

    fn write_file_local(filepath: &Path, data: &[u8]) -> Result<()> {
        let parent_dir = filepath.parent().ok_or_else(|| anyhow!("Invalid filepath, no parent directory: {:?}", filepath))?;
        if !parent_dir.exists() {
            fs::create_dir_all(parent_dir).with_context(|| format!("Failed to create parent directory: {:?}", parent_dir))?;
        }
        
        let temp_filename_str = format!("{}.{}.tmp", 
            filepath.file_name().unwrap_or_default().to_string_lossy(),
            Uuid::new_v4().to_string()
        );
        let temp_filepath = parent_dir.join(temp_filename_str);

        let file = File::create(&temp_filepath).with_context(|| format!("Could not create temporary file: {:?}", temp_filepath))?;
        let mut writer = BufWriter::new(file);
        writer.write_all(data).with_context(|| format!("Failed to write data to temporary file: {:?}", temp_filepath))?;
        writer.flush().with_context(|| format!("Failed to flush BufWriter for temporary file: {:?}", temp_filepath))?;
        writer.into_inner() // Consumes BufWriter, returns inner File
            .map_err(|e| anyhow!("BufWriter into_inner error: {:?}", e.get_ref().map(|r| r.to_string())))?
            .sync_all().with_context(|| format!("Failed to sync temporary file: {:?}", temp_filepath))?;
        
        fs::rename(&temp_filepath, filepath).with_context(|| format!("Failed to rename temporary file {:?} to {:?}", temp_filepath, filepath))?;
        Ok(())
    }

    fn read_file_local(filepath: &Path) -> Result<Option<Vec<u8>>> {
        if !filepath.exists() { return Ok(None); }
        let file = File::open(filepath).with_context(|| format!("Could not open file for reading: {:?}", filepath))?;
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).with_context(|| format!("Failed to read file content from: {:?}", filepath))?;
        Ok(Some(buffer))
    }

    fn secure_delete_file_local(filepath: &Path) -> Result<()> {
        if !filepath.exists() { return Ok(()); }
        let file_size = fs::metadata(filepath)?.len();
        if file_size > 0 {
            let mut file = OpenOptions::new().write(true).open(filepath)?;
            let buffer_size = 4096; // Common block size
            let mut buffer = vec![0u8; buffer_size];
            let mut rng = rand::thread_rng();

            for pass in 0..config::SECURE_ERASE_PASSES {
                file.seek(SeekFrom::Start(0))?;
                if pass == config::SECURE_ERASE_PASSES - 1 {
                    use rand::RngCore; //
                    rng.fill_bytes(&mut buffer);
                } else if pass % 2 == 0 { // Pattern 0x00
                    buffer.iter_mut().for_each(|byte| *byte = 0x00);
                } else { // Pattern 0xFF
                    buffer.iter_mut().for_each(|byte| *byte = 0xFF);
                }
                
                let mut written = 0;
                while written < file_size {
                    let to_write = std::cmp::min(buffer_size as u64, file_size - written) as usize;
                    file.write_all(&buffer[..to_write])?;
                    written += to_write as u64;
                }
                file.sync_all()?;
            }
        }
        fs::remove_file(filepath)?;
        Ok(())
    }
    
    fn erase_all_shards_keys_and_manifests(&mut self) -> Result<()> {
        let mut all_successful = true;
        match self.storage_type {
            StorageType::Local => {
                let key_file = self.get_key_material_filepath();
                if key_file.exists() {
                    if let Err(e) = Self::secure_delete_file_local(&key_file) {
                        eprintln!("Warning: Failed to securely delete local key material file {:?}: {}", key_file, e); all_successful = false;
                    }
                }
                let storage_dir = PathBuf::from(&self.storage_location_identifier);
                if storage_dir.is_dir() {
                    let manifests_dir = storage_dir.join("manifests");
                    if manifests_dir.exists() {
                        // TODO iterate and `secure_delete_file_local` each manifest before removing the dir
                        if let Err(e) = fs::remove_dir_all(&manifests_dir) {
                             eprintln!("Warning: Failed to delete manifests directory {:?}: {}", manifests_dir, e); all_successful = false;
                        }
                    }
                    match fs::read_dir(&storage_dir) {
                        Ok(entries) => {
                            for entry in entries {
                                if let Ok(entry) = entry {
                                    let path = entry.path();
                                    if path.is_file() && path.file_name().map_or(false, |name| name.to_string_lossy().starts_with("shard_") && name.to_string_lossy().ends_with(".dat")) {
                                        if let Err(e) = Self::secure_delete_file_local(&path) {
                                            eprintln!("Warning: Failed to securely delete local shard file {:?}: {}", path, e); all_successful = false;
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => { eprintln!("Warning: Failed to read storage directory {:?} for shard deletion: {}", storage_dir, e); all_successful = false; }
                    }
                }
            }
            _ if self.cloud_client.is_some() => {
                let client = self.cloud_client.as_ref().unwrap();
                if let Err(e) = client.secure_delete_data("metadata/key_material.bin") { eprintln!("Warning: Failed to delete cloud key material: {}", e); all_successful = false; }
                match client.list_objects("manifests/") {
                    Ok(manifest_objects) => {
                        for obj_key in manifest_objects {
                            if obj_key.starts_with("manifests/manifest_") && obj_key.ends_with(".bin") {
                                if let Err(e) = client.secure_delete_data(&obj_key) { eprintln!("Warning: Failed to delete cloud manifest {}: {}", obj_key, e); all_successful = false; }
                            }
                        }
                    }
                    Err(e) => { eprintln!("Warning: Failed to list cloud manifests for deletion: {}", e); all_successful = false; }
                }
                match client.list_objects("shards/") {
                    Ok(shard_objects) => {
                        for obj_key in shard_objects {
                            if obj_key.starts_with("shards/shard_") && obj_key.ends_with(".dat") {
                                if let Err(e) = client.secure_delete_data(&obj_key) { eprintln!("Warning: Failed to delete cloud shard {}: {}", obj_key, e); all_successful = false; }
                            }
                        }
                    }
                    Err(e) => { eprintln!("Warning: Failed to list cloud shards for deletion: {}", e); all_successful = false; }
                }
            }
            _ => return Err(anyhow!("Storage type not local and no cloud client for erasing all data.")),
        }
        if all_successful { Ok(()) } else { Err(anyhow!("Secure erase encountered one or more failures.")) }
    }
}

pub fn calculate_shard_count(data_size_bytes: usize) -> usize {
    if data_size_bytes == 0 { return 0; } // 1 for an empty shard
    let num_shards_for_data = (data_size_bytes + config::MAX_SHARD_SIZE_BYTES - 1) / config::MAX_SHARD_SIZE_BYTES;
    max(config::MIN_SHARDS_STORAGE, num_shards_for_data)
}

// TODO cloud client implementations
struct S3ClientImpl; impl S3ClientImpl { fn new() -> Self { S3ClientImpl } }
impl CloudStorageClient for S3ClientImpl { /* ... stuff ... */ }

