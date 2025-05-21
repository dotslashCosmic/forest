// Author: dotslashCosmic
use crate::{config, crypto, data_structures::DataShard, secure_utils};
use anyhow::{anyhow, Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom, Cursor};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
struct UsbKeyData {
    // Key Encryption Key is derived from the Forest/Burn key to encrypt/decrypt DEK.
    encrypted_main_storage_dek_on_usb: Vec<u8>,
    main_storage_dek_iv: Vec<u8>,

    forest_salt: Vec<u8>,
    burn_salt: Option<Vec<u8>>,
    ember_salt: Option<Vec<u8>>,
    smoke_salt: Option<Vec<u8>>,
    seed_salt: Option<Vec<u8>>,

    stored_forest_key_hash: Vec<u8>,
    stored_burn_key_hash: Option<Vec<u8>>,
    stored_ember_key_hash: Option<Vec<u8>>,
    stored_smoke_key_hash: Option<Vec<u8>>,
    stored_seed_key_hash: Option<Vec<u8>>,

    usb_shard: DataShard,
    uuid: String,
    is_initialized: bool,
}

impl UsbKeyData {
    fn new() -> Self {
        UsbKeyData {
            encrypted_main_storage_dek_on_usb: Vec::new(),
            main_storage_dek_iv: Vec::new(),
            forest_salt: Vec::new(),
            burn_salt: None,
            ember_salt: None,
            smoke_salt: None,
            seed_salt: None,
            stored_forest_key_hash: Vec::new(),
            stored_burn_key_hash: None,
            stored_ember_key_hash: None,
            stored_smoke_key_hash: None,
            stored_seed_key_hash: None,
            usb_shard: DataShard::empty(),
            uuid: String::new(),
            is_initialized: false,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AuthAction {
    AccessRealData,
    AccessRealDataAndSeed,
    AccessDecoyData, // Placeholder- Decoy environment access
    AccessDecoyDataAndSeed, // Placeholder- Decoy environment access + Seed
    OneTimeViewRealData,
    OneTimeViewRealDataAndSeed,
    OneTimeViewDecoyData, // Placeholder- Smoke + Ember for decoy
    OneTimeViewDecoyDataAndSeed, // Placeholder- Smoke + Ember for decoy + Seed
    TriggerBurn,
    TriggerBurnAndSeed,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AuthFailure {
    InvalidKeyInput,
    KeyCombinationNotAllowed,
    UsbNotConnected,
    UsbNotInitialized,
    InternalAuthError(String),
}

pub type AuthenticationOutcome = Result<AuthAction, AuthFailure>;

#[derive(Debug, ZeroizeOnDrop)]
pub struct UsbKey {
    usb_data: UsbKeyData,
    usb_device_path: PathBuf,
    is_connected: bool,
    is_authenticated: bool, // true if a valid key successfully decrypted DEK
    #[zeroize(skip)] // current_main_storage_dek is derived and critical.
    current_main_storage_dek: Vec<u8>, // Decrypted DEK for MainStorage after successful auth
}

#[derive(Debug, Clone, Copy)]
enum KeyComponentType {
    Forest,
    Burn,
    Ember,
    Smoke,
    Seed,
}

#[derive(Debug)]
struct ParsedKeyInput<'a> {
    base_action_type: BaseActionType,
    base_secret_input: &'a str,
    seed_secret_input: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
enum BaseActionType {
    Forest,
    Burn,
    Ember,
    Smoke,
    SmokeAndEmber,
}


impl UsbKey {
    pub fn new() -> Result<Self> {
        let mut key = UsbKey {
            usb_data: UsbKeyData::new(),
            usb_device_path: PathBuf::new(),
            is_connected: false,
            is_authenticated: false,
            current_main_storage_dek: Vec::new(),
        };
        key.connect_to_usb_device()?;
        if key.is_connected {
            match key.read_and_deserialize_usb_data() {
                Ok(_) => println!("Existing Root Key data loaded."),
                Err(e) => {
                    // fine if the key isn't initialized yet or file doesn't exist
                    eprintln!("Debug: Failed to load existing Root Key data: {}. Assuming new/uninitialized.", e);
                    key.usb_data.is_initialized = false;
                }
            }
        }
        Ok(key)
    }

    pub fn initialize(
        &mut self,
        forest_secret: &str,
        burn_secret: Option<&str>,
        ember_secret: Option<&str>,
        smoke_secret: Option<&str>,
        seed_secret: Option<&str>,
    ) -> Result<()> {
        if !self.is_connected {
            return Err(anyhow!(AuthFailure::UsbNotConnected.to_string_for_anyhow()));
        }
        if self.usb_data.is_initialized {
            return Err(anyhow!("Root Key is already initialized."));
        }
        if forest_secret.is_empty() {
            return Err(anyhow!("Forest secret cannot be empty during initialization."));
        }

        self.usb_data.uuid = Uuid::new_v4().to_string();
        self.usb_data.forest_salt = crypto::generate_random_bytes(config::SALT_LENGTH)?;
        
        let mut derived_forest_key_for_hash = Self::derive_internal_key_for_hash(forest_secret, &self.usb_data.forest_salt)?;
        self.usb_data.stored_forest_key_hash = crypto::hash_sha3_512(&derived_forest_key_for_hash)?;
        derived_forest_key_for_hash.zeroize();

        let mut setup_optional_key = |secret_opt: Option<&str>, salt_field: &mut Option<Vec<u8>>, hash_field: &mut Option<Vec<u8>>| -> Result<()> {
            if let Some(secret) = secret_opt {
                if !secret.is_empty() {
                    let salt = crypto::generate_random_bytes(config::SALT_LENGTH)?;
                    let mut derived_key_for_hash = Self::derive_internal_key_for_hash(secret, &salt)?;
                    *hash_field = Some(crypto::hash_sha3_512(&derived_key_for_hash)?);
                    *salt_field = Some(salt);
                    derived_key_for_hash.zeroize();
                } else { // keep Some("") as None for consistency
                    *salt_field = None;
                    *hash_field = None;
                }
            }
            Ok(())
        };

        setup_optional_key(burn_secret, &mut self.usb_data.burn_salt, &mut self.usb_data.stored_burn_key_hash)?;
        setup_optional_key(ember_secret, &mut self.usb_data.ember_salt, &mut self.usb_data.stored_ember_key_hash)?;
        setup_optional_key(smoke_secret, &mut self.usb_data.smoke_salt, &mut self.usb_data.stored_smoke_key_hash)?;
        
        // Setup Seed key (if provided)
        if let Some(secret) = seed_secret {
            if !secret.is_empty() {
                let salt = crypto::generate_random_bytes(config::SALT_LENGTH)?;
                let mut derived_seed_key_for_hash = Self::derive_internal_key_for_hash(secret, &salt)?;
                self.usb_data.stored_seed_key_hash = Some(crypto::hash_sha3_512(&derived_seed_key_for_hash)?);
                self.usb_data.seed_salt = Some(salt);
                derived_seed_key_for_hash.zeroize();
            }
        }

        let mut initial_main_storage_dek = crypto::generate_random_bytes(config::DEK_LENGTH)?;
        let mut kek_for_dek_encryption = Self::derive_internal_key_for_kek(forest_secret, &self.usb_data.forest_salt)?;

        let (encrypted_dek, iv) = crypto::encrypt_xchacha20_poly1305(&initial_main_storage_dek, &kek_for_dek_encryption)?;
        self.usb_data.encrypted_main_storage_dek_on_usb = encrypted_dek;
        self.usb_data.main_storage_dek_iv = iv;
        
        initial_main_storage_dek.zeroize();
        kek_for_dek_encryption.zeroize();

        self.usb_data.usb_shard = DataShard::new(config::USB_KEY_SHARD_INDEX as i32, Vec::new(), Vec::new());
        self.usb_data.is_initialized = true;

        self.serialize_and_write_usb_data()
            .with_context(|| "Failed to write initial data to Root Key.")?;
        
        println!("Root Key initialized successfully with UUID: {}", self.usb_data.uuid);
        Ok(())
    }

    fn verify_secret_part(&self, secret_part_input: &str, component_type: KeyComponentType) -> bool {
        if secret_part_input.is_empty() {
            return false;
        }

        let (salt_opt, stored_hash_opt) = match component_type {
            KeyComponentType::Forest => (Some(&self.usb_data.forest_salt), Some(&self.usb_data.stored_forest_key_hash)),
            KeyComponentType::Burn   => (self.usb_data.burn_salt.as_ref(), self.usb_data.stored_burn_key_hash.as_ref()),
            KeyComponentType::Ember  => (self.usb_data.ember_salt.as_ref(), self.usb_data.stored_ember_key_hash.as_ref()),
            KeyComponentType::Smoke  => (self.usb_data.smoke_salt.as_ref(), self.usb_data.stored_smoke_key_hash.as_ref()),
            KeyComponentType::Seed   => (self.usb_data.seed_salt.as_ref(), self.usb_data.stored_seed_key_hash.as_ref()),
        };

        if let (Some(salt), Some(stored_hash)) = (salt_opt, stored_hash_opt) {
            if let Ok(mut derived_key) = Self::derive_internal_key_for_hash(secret_part_input, salt) {
                if let Ok(input_hash) = crypto::hash_sha3_512(&derived_key) {
                    derived_key.zeroize();
                    return secure_utils::constant_time_compare(&input_hash, stored_hash);
                }
                derived_key.zeroize();
            }
        }
        false
    }
    
    fn parse_key_input_string<'a>(&self, key_input_str: &'a str) -> Result<ParsedKeyInput<'a>, AuthFailure> {
        if key_input_str.is_empty() {
            return Err(AuthFailure::InvalidKeyInput);
        }

        let mut base_input_part = key_input_str;
        let mut seed_input_part = None;

        if self.usb_data.seed_salt.is_some() && self.usb_data.stored_seed_key_hash.is_some() {
            for i in (1..=base_input_part.len()).rev() {
                if i > base_input_part.len() { continue; }
                let potential_seed_part = &base_input_part[base_input_part.len() - i..];
                let remaining_base_part = &base_input_part[..base_input_part.len() - i];
                
                if self.verify_secret_part(potential_seed_part, KeyComponentType::Seed) {
                    seed_input_part = Some(potential_seed_part);
                    base_input_part = remaining_base_part;
                    break; 
                }
            }
        }
        
        if base_input_part.is_empty() && seed_input_part.is_none() {
            return Err(AuthFailure::InvalidKeyInput);
        }
         if base_input_part.is_empty() && seed_input_part.is_some() {
            return Err(AuthFailure::InvalidKeyInput);
        }


        // Order: Burn > Smoke+Ember > Smoke > Ember > Forest

        // Check for Burn
        if self.usb_data.burn_salt.is_some() && self.verify_secret_part(base_input_part, KeyComponentType::Burn) {
            return Ok(ParsedKeyInput {
                base_action_type: BaseActionType::Burn,
                base_secret_input: base_input_part,
                seed_secret_input: seed_input_part,
            });
        }

        // Check for SmokeAndEmber combination
        if self.usb_data.smoke_salt.is_some() && self.usb_data.ember_salt.is_some() {
            for i in (1..base_input_part.len()).rev() {
                let potential_smoke_part = &base_input_part[..i];
                let potential_ember_part = &base_input_part[i..];

                if !potential_smoke_part.is_empty() && !potential_ember_part.is_empty() &&
                   self.verify_secret_part(potential_smoke_part, KeyComponentType::Smoke) &&
                   self.verify_secret_part(potential_ember_part, KeyComponentType::Ember) {
                    return Ok(ParsedKeyInput {
                        base_action_type: BaseActionType::SmokeAndEmber,
                        base_secret_input: base_input_part,
                        seed_secret_input: seed_input_part,
                    });
                }
            }
        }

        // Check for Smoke
        if self.usb_data.smoke_salt.is_some() && self.verify_secret_part(base_input_part, KeyComponentType::Smoke) {
            return Ok(ParsedKeyInput {
                base_action_type: BaseActionType::Smoke,
                base_secret_input: base_input_part,
                seed_secret_input: seed_input_part,
            });
        }

        // Check for Ember
        if self.usb_data.ember_salt.is_some() && self.verify_secret_part(base_input_part, KeyComponentType::Ember) {
            return Ok(ParsedKeyInput {
                base_action_type: BaseActionType::Ember,
                base_secret_input: base_input_part,
                seed_secret_input: seed_input_part,
            });
        }

        // Check for Forest
        if self.verify_secret_part(base_input_part, KeyComponentType::Forest) {
            return Ok(ParsedKeyInput {
                base_action_type: BaseActionType::Forest,
                base_secret_input: base_input_part,
                seed_secret_input: seed_input_part,
            });
        }

        Err(AuthFailure::InvalidKeyInput)
    }


    pub fn authenticate(&mut self, key_input_str: &str) -> AuthenticationOutcome {
        if !self.is_connected { return Err(AuthFailure::UsbNotConnected); }
        if !self.usb_data.is_initialized { return Err(AuthFailure::UsbNotInitialized); }
        
        self.is_authenticated = false;
        self.current_main_storage_dek.zeroize();
        self.current_main_storage_dek.clear();

        // Ensure USB data is loaded (it should be if initialize or new succeeded and found data)
        if self.usb_data.uuid.is_empty() && self.usb_data.is_initialized {
             // TODO implies an inconsistent state; initialized flag is true but UUID is missing
             // TODO Attemp a re-read, or fail, error currently
            return Err(AuthFailure::InternalAuthError("USB data inconsistent (initialized but no UUID).".to_string()));
        }


        let parsed_input = match self.parse_key_input_string(key_input_str) {
            Ok(p) => p,
            Err(e) => return Err(e),
        };

        let has_seed = parsed_input.seed_secret_input.is_some();

        match parsed_input.base_action_type {
            BaseActionType::Burn => {
                // Burn action takes precedence, no DEK decryption.
                if has_seed { Ok(AuthAction::TriggerBurnAndSeed) } else { Ok(AuthAction::TriggerBurn) }
            }
            BaseActionType::SmokeAndEmber => {
                // TODO implement decoy environment logic, no DEK currently.
                if has_seed { Ok(AuthAction::OneTimeViewDecoyDataAndSeed) } else { Ok(AuthAction::OneTimeViewDecoyData) }
            }
            BaseActionType::Smoke => {
                // TODO implement decoy environment logic, no DEK currently.
                if has_seed { Ok(AuthAction::AccessDecoyDataAndSeed) } else { Ok(AuthAction::AccessDecoyData) }
            }
            BaseActionType::Ember => {
                if let Some(ember_salt) = &self.usb_data.ember_salt {
                    match Self::derive_internal_key_for_kek(parsed_input.base_secret_input, ember_salt) {
                        Ok(mut kek) => {
                            match crypto::decrypt_xchacha20_poly1305(
                                &self.usb_data.encrypted_main_storage_dek_on_usb,
                                &kek,
                                &self.usb_data.main_storage_dek_iv,
                            ) {
                                Ok(decrypted_dek) => {
                                    self.current_main_storage_dek = decrypted_dek;
                                    self.is_authenticated = true;
                                    kek.zeroize();
                                    if has_seed { Ok(AuthAction::OneTimeViewRealDataAndSeed) } else { Ok(AuthAction::OneTimeViewRealData) }
                                }
                                Err(e) => {
                                    kek.zeroize();
                                    Err(AuthFailure::InternalAuthError(format!("Ember DEK decryption failed: {}", e)))
                                }
                            }
                        }
                        Err(e) => Err(AuthFailure::InternalAuthError(format!("Ember KEK derivation failed: {}", e))),
                    }
                } else {
                     Err(AuthFailure::InternalAuthError("Ember salt missing for Ember key.".to_string()))
                }
            }
            BaseActionType::Forest => {
                 match Self::derive_internal_key_for_kek(parsed_input.base_secret_input, &self.usb_data.forest_salt) {
                    Ok(mut kek) => {
                        match crypto::decrypt_xchacha20_poly1305(
                            &self.usb_data.encrypted_main_storage_dek_on_usb,
                            &kek,
                            &self.usb_data.main_storage_dek_iv,
                        ) {
                            Ok(decrypted_dek) => {
                                self.current_main_storage_dek = decrypted_dek;
                                self.is_authenticated = true;
                                kek.zeroize();
                                if has_seed { Ok(AuthAction::AccessRealDataAndSeed) } else { Ok(AuthAction::AccessRealData) }
                            }
                            Err(e) => {
                                kek.zeroize();
                                Err(AuthFailure::InternalAuthError(format!("Forest DEK decryption failed: {}", e)))
                            }
                        }
                    }
                    Err(e) => Err(AuthFailure::InternalAuthError(format!("Forest KEK derivation failed: {}", e))),
                }
            }
        }
    }

    pub fn get_decrypted_main_storage_dek(&self) -> Result<Vec<u8>> {
        if self.is_authenticated && !self.current_main_storage_dek.is_empty() {
            Ok(self.current_main_storage_dek.clone())
        } else {
            Err(anyhow!("Not authenticated or DEK not available. Call authenticate first."))
        }
    }

    pub fn store_usb_shard(&mut self, shard_data: DataShard) -> Result<()> {
        if !self.is_connected { return Err(anyhow!(AuthFailure::UsbNotConnected.to_string_for_anyhow())); }
        if !self.usb_data.is_initialized { return Err(anyhow!(AuthFailure::UsbNotInitialized.to_string_for_anyhow())); }
        if !shard_data.is_valid() { return Err(anyhow!("Invalid shard data provided for Root Key.")); }
        
        self.usb_data.usb_shard = shard_data;
        self.serialize_and_write_usb_data()
            .with_context(|| "Failed to write updated data shard to Root Key.")
    }

    pub fn retrieve_usb_shard(&self) -> Result<DataShard> {
        if !self.is_connected { return Err(anyhow!(AuthFailure::UsbNotConnected.to_string_for_anyhow())); }
        if !self.usb_data.is_initialized { return Err(anyhow!(AuthFailure::UsbNotInitialized.to_string_for_anyhow())); }
        Ok(self.usb_data.usb_shard.clone())
    }

    pub fn secure_erase_usb_data(&mut self) -> Result<()> {
        if !self.is_connected { return Err(anyhow!("Root Key not connected. Cannot perform secure erase.")); }
        println!("Performing secure erasure of Root Key data...");
        
        self.usb_data.zeroize(); 
        self.current_main_storage_dek.zeroize();
        self.is_authenticated = false;
        // TODO explicit reset on fields after zeroizing UsbKeyData
        self.usb_data = UsbKeyData::new();

        let data_filepath = self.get_usb_data_filepath();
        if data_filepath.exists() {
            Self::secure_delete_usb_file(&data_filepath)
                .with_context(|| format!("Failed to securely delete data file from Root Key: {:?}", data_filepath))?;
        }
        println!("Root Key data securely erased.");
        Ok(())
    }
    
    pub fn get_uuid(&self) -> Result<String> {
        if !self.is_connected { return Err(anyhow!(AuthFailure::UsbNotConnected.to_string_for_anyhow())); }
        if !self.usb_data.is_initialized || self.usb_data.uuid.is_empty() {
            // TODO mutable and read is problematic in immutable method
            // assume if `is_initialized` is true, `uuid` is populated.
            // if not initialized, then it's an error to ask for UUID.
            if !self.usb_data.is_initialized {
                 return Err(anyhow!(AuthFailure::UsbNotInitialized.to_string_for_anyhow()));
            }
            // If initialized but UUID is empty, this is an inconsistent state.
            if self.usb_data.uuid.is_empty() {
                return Err(anyhow!("Root Key is initialized but UUID is missing. Data may be corrupt, or Root Key is cloned."));
            }
        }
        Ok(self.usb_data.uuid.clone())
    }

    pub fn has_secure_element(&self) -> bool {
        eprintln!("Warning: has_secure_element is a placeholder.");
        false
    }

    pub fn is_key_connected(&self) -> bool { self.is_connected }
    pub fn is_key_initialized(&self) -> bool { self.usb_data.is_initialized }


    // --- Internal Helper Methods ---
    fn derive_internal_key_for_kek(input_secret: &str, salt: &[u8]) -> Result<Vec<u8>> {
        crypto::derive_key_argon2(input_secret, salt, config::KEK_LENGTH)
    }
    
    fn derive_internal_key_for_hash(input_secret: &str, salt: &[u8]) -> Result<Vec<u8>> {
        crypto::derive_key_argon2(input_secret, salt, config::KEK_LENGTH) 
    }

    fn get_usb_data_filepath(&self) -> PathBuf {
        self.usb_device_path.join("forest_data.bin") 
    }

    // Reads and deserializes UsbKeyData from the root key.
    // TODO replace de/serialization with serde + bincode or similar.
    fn read_and_deserialize_usb_data(&mut self) -> Result<()> {
        if !self.is_connected { return Err(anyhow!("Root Key not connected.")); }
        let filepath = self.get_usb_data_filepath();
        let serialized_data_opt = Self::read_usb_file(&filepath)
            .with_context(|| format!("Failed to read Root Key data file: {:?}", filepath))?;
        
        let serialized_data = match serialized_data_opt {
            Some(data) if !data.is_empty() => data,
            _ => return Err(anyhow!("Root Key data file not found or empty: {:?}", filepath)),
        };

        let mut cursor = Cursor::new(serialized_data.as_slice());
        
        let read_vec = |c: &mut Cursor<&[u8]>| -> Result<Vec<u8>> {
            let mut len_bytes = [0u8; 4];
            c.read_exact(&mut len_bytes).context("Failed to read length for vector")?;
            let len = u32::from_le_bytes(len_bytes) as usize;
            if len > 2 * 1024 * 1024 { return Err(anyhow!("Serialized vec too large: {} bytes", len)); } 
            let mut data = vec![0u8; len];
            if len > 0 { c.read_exact(&mut data).context("Failed to read vector data")?; }
            Ok(data)
        };
        let read_opt_vec = |c: &mut Cursor<&[u8]>| -> Result<Option<Vec<u8>>> {
            let mut flag = [0u8; 1];
            c.read_exact(&mut flag).context("Failed to read option flag for vector")?;
            if flag[0] == 1 { Ok(Some(read_vec(c)?)) } else { Ok(None) }
        };

        self.usb_data.encrypted_main_storage_dek_on_usb = read_vec(&mut cursor).context("Deserialize encrypted_main_storage_dek_on_usb")?;
        self.usb_data.main_storage_dek_iv = read_vec(&mut cursor).context("Deserialize main_storage_dek_iv")?;
        self.usb_data.forest_salt = read_vec(&mut cursor).context("Deserialize forest_salt")?;
        self.usb_data.burn_salt = read_opt_vec(&mut cursor).context("Deserialize burn_salt")?;
        self.usb_data.ember_salt = read_opt_vec(&mut cursor).context("Deserialize ember_salt")?;
        self.usb_data.smoke_salt = read_opt_vec(&mut cursor).context("Deserialize smoke_salt")?;
        self.usb_data.seed_salt = read_opt_vec(&mut cursor).context("Deserialize seed_salt")?;
        
        self.usb_data.stored_forest_key_hash = read_vec(&mut cursor).context("Deserialize stored_forest_key_hash")?;
        self.usb_data.stored_burn_key_hash = read_opt_vec(&mut cursor).context("Deserialize stored_burn_key_hash")?;
        self.usb_data.stored_ember_key_hash = read_opt_vec(&mut cursor).context("Deserialize stored_ember_key_hash")?;
        self.usb_data.stored_smoke_key_hash = read_opt_vec(&mut cursor).context("Deserialize stored_smoke_key_hash")?;
        self.usb_data.stored_seed_key_hash = read_opt_vec(&mut cursor).context("Deserialize stored_seed_key_hash")?;


        self.usb_data.usb_shard.data = read_vec(&mut cursor).context("Deserialize usb_shard.data")?;
        self.usb_data.usb_shard.shard_index = config::USB_KEY_SHARD_INDEX as i32; 
        self.usb_data.usb_shard.integrity_hash = read_vec(&mut cursor).context("Deserialize usb_shard.integrity_hash")?;
        
        let uuid_str_bytes = read_vec(&mut cursor).context("Deserialize uuid_str_bytes")?;
        self.usb_data.uuid = String::from_utf8(uuid_str_bytes).context("Failed to decode UUID from UTF-8")?;
        
        let mut init_flag_byte = [0u8; 1];
        cursor.read_exact(&mut init_flag_byte).context("Deserialize init_flag_byte")?;
        self.usb_data.is_initialized = init_flag_byte[0] == 1;

        if cursor.position() != serialized_data.len() as u64 {
            eprintln!("Warning: Trailing data in Root Key deserialization. Consumed: {}, Total: {}", cursor.position(), serialized_data.len());
            // corrupted file/mismatch in serialization/deserialization logic as error
            return Err(anyhow!("Trailing data after Root Key deserialization, data may be corrupt."));
        }

        Ok(())
    }

    // Serializes and writes UsbKeyData to the root key.
    // TODO replace de/serialization with serde + bincode or similar.
    fn serialize_and_write_usb_data(&self) -> Result<()> {
        if !self.is_connected { return Err(anyhow!("Root Key not connected.")); }
        let mut serialized_data = Vec::new();
        
        let write_vec = |writer: &mut Vec<u8>, data: &[u8]| -> Result<()> {
            writer.write_all(&(data.len() as u32).to_le_bytes())?;
            writer.write_all(data)?;
            Ok(())
        };
        let write_opt_vec = |writer: &mut Vec<u8>, data_opt: &Option<Vec<u8>>| -> Result<()> {
            if let Some(data) = data_opt {
                writer.write_all(&[1u8])?; 
                write_vec(writer, data)?;
            } else {
                writer.write_all(&[0u8])?;
            }
            Ok(())
        };

        write_vec(&mut serialized_data, &self.usb_data.encrypted_main_storage_dek_on_usb)?;
        write_vec(&mut serialized_data, &self.usb_data.main_storage_dek_iv)?;
        write_vec(&mut serialized_data, &self.usb_data.forest_salt)?;
        write_opt_vec(&mut serialized_data, &self.usb_data.burn_salt)?;
        write_opt_vec(&mut serialized_data, &self.usb_data.ember_salt)?;
        write_opt_vec(&mut serialized_data, &self.usb_data.smoke_salt)?;
        write_opt_vec(&mut serialized_data, &self.usb_data.seed_salt)?;

        write_vec(&mut serialized_data, &self.usb_data.stored_forest_key_hash)?;
        write_opt_vec(&mut serialized_data, &self.usb_data.stored_burn_key_hash)?;
        write_opt_vec(&mut serialized_data, &self.usb_data.stored_ember_key_hash)?;
        write_opt_vec(&mut serialized_data, &self.usb_data.stored_smoke_key_hash)?;
        write_opt_vec(&mut serialized_data, &self.usb_data.stored_seed_key_hash)?;


        write_vec(&mut serialized_data, &self.usb_data.usb_shard.data)?;
        write_vec(&mut serialized_data, &self.usb_data.usb_shard.integrity_hash)?; // Assuming this is always present even if empty
        write_vec(&mut serialized_data, self.usb_data.uuid.as_bytes())?;
        serialized_data.write_all(&[if self.usb_data.is_initialized { 1u8 } else { 0u8 }])?;

        let filepath = self.get_usb_data_filepath();
        Self::write_usb_file(&filepath, &serialized_data)
            .with_context(|| format!("Failed to write Root Key data file: {:?}", filepath))
    }

    fn detect_usb_device() -> Result<PathBuf> {
        #[cfg(target_os = "windows")]
        {
            for drive in ['E', 'F', 'G', 'H', 'I', 'J'].iter() {
                let path = format!("{}:\\", drive);
                if fs::metadata(&path).is_ok() {
                    return Ok(PathBuf::from(path));
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            let paths = fs::read_dir("/Volumes")?;
            for entry in paths {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    return Ok(entry.path());
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            let paths = fs::read_dir("/media")?;
            for entry in paths {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    return Ok(entry.path());
                }
            }
        }
        Err(anyhow!("No Root Key found."))
    }

    fn connect_to_usb_device(&mut self) -> Result<()> {
        self.usb_device_path = detect_usb_device()?;
        
        if !self.usb_device_path.exists() {
            return Err(anyhow!("Root Key not found at path: {:?}", self.usb_device_path));
        }
        self.is_connected = true;
        println!("Connected to Root Key at: {:?}", self.usb_device_path);
        Ok(())
    }

    fn disconnect_from_usb_device(&mut self) {
        self.is_connected = false;
        self.is_authenticated = false;
        self.current_main_storage_dek.zeroize();
    }
    
    fn read_usb_file(filepath: &Path) -> Result<Option<Vec<u8>>> {
        if !filepath.exists() { return Ok(None); }
        let mut file = File::open(filepath).with_context(|| format!("Could not open Root Key file for reading: {:?}", filepath))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).with_context(|| format!("Failed to read Root Key file content from: {:?}", filepath))?;
        Ok(Some(buffer))
    }

    fn write_usb_file(filepath: &Path, data: &[u8]) -> Result<()> {
        let parent_dir = filepath.parent().ok_or_else(|| anyhow!("Invalid filepath for Root Key write: no parent directory."))?;
        if !parent_dir.exists() {
            fs::create_dir_all(parent_dir).context("Failed to create parent directory for Root Key file.")?;
        }

        let mut file = File::create(filepath).with_context(|| format!("Could not create Root Key file: {:?}", filepath))?;
        file.write_all(data).with_context(|| format!("Failed to write data to Root Key file: {:?}", filepath))?;
        file.sync_all().with_context(|| format!("Failed to sync Root Key file: {:?}", filepath))?;
        Ok(())
    }

    fn secure_delete_usb_file(filepath: &Path) -> Result<()> {
        if !filepath.exists() { return Ok(()); }
        let file_size = fs::metadata(filepath)?.len();
        if file_size > 0 {
            let mut file = OpenOptions::new().write(true).open(filepath)?;
            let buffer_size = 1024; 
            let mut buffer = vec![0u8; buffer_size];
            let mut rng = rand::thread_rng();

            for pass in 0..config::SECURE_ERASE_PASSES { 
                file.seek(SeekFrom::Start(0))?;
                
                if pass == config::SECURE_ERASE_PASSES - 1 {
                    use rand::Rng;
                    rng.fill(&mut buffer[..]);
                } else if pass % 2 == 0 { // 0x00 or other fixed patterns
                     for byte in buffer.iter_mut() { *byte = 0x00; }
                } else { // 0xFF or other fixed patterns
                     for byte in buffer.iter_mut() { *byte = 0xFF; }
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
}

impl Drop for UsbKey {
    fn drop(&mut self) {
        if self.is_connected {
            self.disconnect_from_usb_device(); 
        }
        // self.usb_data will be zeroized by own ZeroizeOnDrop
        self.current_main_storage_dek.zeroize();
    }
}

impl AuthFailure {
    fn to_string_for_anyhow(&self) -> String {
        match self {
            AuthFailure::InvalidKeyInput => "InvalidKeyInput: The provided key string is invalid or unrecognized.".to_string(),
            AuthFailure::KeyCombinationNotAllowed => "KeyCombinationNotAllowed: The parsed key combination is not permitted.".to_string(),
            AuthFailure::UsbNotConnected => "UsbNotConnected: The Root Key is not connected.".to_string(),
            AuthFailure::UsbNotInitialized => "UsbNotInitialized: The Root Key requires initialization.".to_string(),
            AuthFailure::InternalAuthError(s) => format!("InternalAuthError: {}", s),
        }
    }
}
