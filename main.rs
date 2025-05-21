use eframe::{egui, NativeOptions};
use std::path::PathBuf;
use std::sync::Mutex; // cross-thread logging

mod forest_lib {
    pub mod config {
        pub const DEFAULT_MAIN_STORAGE_PATH: &str = "./forest_main_storage_gui";
        pub const KEK_LENGTH: usize = 32;
    }
    pub mod crypto {
        // stubs for GUI comp
        pub fn generate_random_bytes(_len: usize) -> Result<Vec<u8>, lib::ForestError> {
            Ok(vec![0u8; 32]) //TODO replace
        }
    }
    pub mod data_structures {
        use serde::{Deserialize, Serialize};
        use zeroize::Zeroize;
        #[derive(Debug, Clone, Zeroize, Serialize, Deserialize, Default)]
        #[zeroize(drop)]
        pub struct DataShard {
            pub data: Vec<u8>,
            pub shard_index: i32,
            pub integrity_hash: Vec<u8>,
        }
        impl DataShard {
            pub fn new(index: i32, data: Vec<u8>, hash: Vec<u8>) -> Self { Self {data, shard_index: index, integrity_hash: hash} }
            pub fn empty() -> Self { Self::default() }
            pub fn is_valid(&self) -> bool { self.shard_index != -1 && !self.data.is_empty() }
        }
    }
    pub mod lib {
        use thiserror::Error;
        #[derive(Error, Debug)]
        pub enum ForestError {
            #[error("Config error: {0}")] ConfigError(String),
            #[error("Crypto error: {0}")] CryptoError(String),
            #[error("Integrity error: {0}")] IntegrityError(String),
            #[error("I/O error: {0}")] IoError(String),
            #[error("Storage error: {0}")] StorageError(String),
            #[error("Root Key error: {0}")] UsbKeyError(String),
            #[error("Sharding error: {0}")] ShardingError(String),
            #[error("Serialization error: {0}")] SerializationError(String),
            #[error("Authentication failed: {0}")] AuthError(String),
            #[error("Initialization required: {0}")] NotInitialized(String),
            #[error("Resource not found: {0}")] NotFound(String),
            #[error("Invalid input: {0}")] InvalidInput(String),
            #[error("Operation failed: {0}")] OperationFailed(String),
        }
        impl From<std::io::Error> for ForestError {
            fn from(err: std::io::Error) -> Self { ForestError::IoError(err.to_string()) }
        }
    }
    pub mod main_storage {
        use super::lib::ForestError;
        use super::data_structures::DataShard;
        use std::path::Path;

        #[derive(Debug)]
        pub enum StorageType { Local }
        #[derive(Debug, Default)]
        pub struct MainStorage { pub is_initialized: bool, pub path: String }
        impl MainStorage {
            pub fn new(_loc: String, _st_type: StorageType, _cfg: Option<CloudConfig>) -> Self { Self {is_initialized: false, path: _loc} }
            pub fn initialize(&mut self) -> Result<(), ForestError> { self.is_initialized = true; Ok(()) }
            pub fn store_shard(&self, _idx: i32, _shard: &DataShard) -> Result<(), ForestError> { Ok(()) }
            pub fn retrieve_shard(&self, _idx: i32) -> Result<DataShard, ForestError> { Ok(DataShard::empty()) }
            pub fn store_manifest_data(&self, _file_id: &str, _data: &[u8]) -> Result<(), ForestError> { Ok(()) }
            pub fn retrieve_manifest_data(&self, _file_id: &str) -> Result<Option<Vec<u8>>, ForestError> { Ok(None) }
            pub fn secure_erase_all_data(&mut self) -> Result<(), ForestError> { Ok(()) }
        }
        #[derive(Debug)]
        pub struct CloudConfig; //TODO cloud shit
    }
    pub mod sharding {
         use super::lib::ForestError;
         use super::data_structures::DataShard;
         use super::main_storage::MainStorage;
         use super::usb_key::UsbKey;
         use std::path::Path;
         use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug, Clone, Default)]
        pub struct FileManifest { pub file_id: String, pub original_filename: String, pub original_file_size: u64, pub total_shards: usize, pub shard_info: Vec<ShardInfo> }
        #[derive(Serialize, Deserialize, Debug, Clone, Default)]
        pub struct ShardInfo { pub shard_index: i32, pub nonce: Vec<u8>, pub encrypted_data_hash: Vec<u8>, pub storage_location: ShardStorageLocation }
        #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
        pub enum ShardStorageLocation { #[default] UsbKey, MainStorage { index_in_main_storage: i32 } }

        pub fn shard_file(_p: &Path, _dek: &[u8], _id: &str) -> Result<(FileManifest, Vec<DataShard>), ForestError> { Ok((FileManifest::default(), Vec::new())) }
        pub fn reconstruct_file(_m: &FileManifest, _dek: &[u8], _o: &Path, _uk: &UsbKey, _ms: &MainStorage) -> Result<(), ForestError> { Ok(()) }
        pub fn store_manifest(_ms: &MainStorage, _m: &FileManifest, _dek: &[u8]) -> Result<(), ForestError> { Ok(()) }
        pub fn retrieve_manifest(_ms: &MainStorage, _id: &str, _dek: &[u8]) -> Result<FileManifest, ForestError> { Ok(FileManifest::default()) }
    }
    pub mod usb_key {
        use super::lib::ForestError;
        use super::data_structures::DataShard;
        #[derive(Debug)]
        pub struct UsbKey { pub is_init: bool, pub is_auth: bool, uuid_val: String }
        #[derive(Debug, PartialEq, Eq)]
        pub enum AuthOutcome { Success, SuccessSeedTriggered, BurnTriggered, EmberTriggered, SmokeTriggered, Failed(ForestError) }
        impl UsbKey {
            pub fn new() -> Result<Self, ForestError> { Ok(Self {is_init: false, is_auth: false, uuid_val: "UUID-GOES-HERE".to_string()}) } // TODO replace dummy
            pub fn initialize(&mut self, _f: &str, _b: Option<&str>, _e: Option<&str>, _s: Option<&str>, _sd: Option<&str>) -> Result<(), ForestError> { self.is_init = true; Ok(()) }
            pub fn authenticate(&mut self, _k: &str) -> AuthOutcome { AuthOutcome::Failed(ForestError::AuthError("Not implemented".to_string())) }
            pub fn get_decrypted_main_storage_dek(&self) -> Result<Vec<u8>, ForestError> { Ok(vec![0;32]) }
            pub fn store_usb_shard(&mut self, _s: DataShard) -> Result<(), ForestError> { Ok(()) }
            pub fn retrieve_usb_shard(&self) -> Result<DataShard, ForestError> { Ok(DataShard::empty()) }
            pub fn secure_erase_usb_data(&mut self) -> Result<(), ForestError> { self.is_init = false; self.is_auth = false; Ok(()) }
            pub fn get_uuid(&mut self) -> Result<String, ForestError> { Ok(self.uuid_val.clone()) }
            pub fn is_key_connected(&self) -> bool { true } // TODO replace
            pub fn is_key_initialized(&self) -> bool { self.is_init }
        }
    }
}


#[derive(PartialEq, Debug, Clone, Copy)]
enum Tab {
    Home,
    KeyManagement,
    DataOperations,
    Settings,
    Logs,
}

#[derive(PartialEq, Debug, Clone, Copy)]
enum HomeActionState {
    Idle,
    ShowingInitializePopup,
    ShowingAuthPopup,
    ShowingBurnConfirmPopup,
}

struct MyApp {
    // Secrets
    init_forest_secret: String,
    init_burn_secret: String,
    init_ember_secret: String,
    init_smoke_secret: String,
    init_seed_secret: String,
    auth_key_input: String,

    // Logs
    log_messages: Vec<String>,
    status_message: String,

    // Backend
    usb_key_manager: Option<forest_lib::usb_key::UsbKey>,
    main_storage_manager: Option<forest_lib::main_storage::MainStorage>,
    main_storage_dek: Vec<u8>, // Decrypted DEK after auth

    // Paths for sharding and reconstruction
    file_to_shard_path: String,
    reconstructed_file_output_path: String,
    manifest_file_id_for_reconstruction: String,

    // GUI State
    active_tab: Tab,
    home_action_state: HomeActionState,
    selected_main_storage_type: forest_lib::main_storage::StorageType, // default to Local
    main_storage_path_input: String,
    // TODO cloud config inputs
}

impl Default for MyApp {
    fn default() -> Self {
        let mut app = Self {
            init_forest_secret: String::new(),
            init_burn_secret: String::new(),
            init_ember_secret: String::new(),
            init_smoke_secret: String::new(),
            init_seed_secret: String::new(),
            auth_key_input: String::new(),
            log_messages: Vec::new(),
            status_message: "Application started. Root Key status unknown.".to_string(),
            usb_key_manager: None,
            main_storage_manager: None,
            main_storage_dek: Vec::new(),
            file_to_shard_path: String::new(),
            reconstructed_file_output_path: String::new(),
            manifest_file_id_for_reconstruction: String::new(),
            active_tab: Tab::Home,
            home_action_state: HomeActionState::Idle,
            selected_main_storage_type: forest_lib::main_storage::StorageType::Local,
            main_storage_path_input: forest_lib::config::DEFAULT_MAIN_STORAGE_PATH.to_string(),
        };
        app.log_message("Attempting to connect to Root Key...");
        match forest_lib::usb_key::UsbKey::new() {
            Ok(mut uk) => {
                if uk.is_key_connected() {
                    let init_status = if uk.is_key_initialized() {
                        "Initialized."
                    } else {
                        "Connected, but NOT Initialized."
                    };
                    app.status_message = format!("Root Key: {}", init_status);
                    app.log_message(format!("Root Key status: {}", init_status));
                    if uk.is_key_initialized() {
                        match uk.get_uuid() {
                            Ok(uuid) => app.log_message(format!("Root Key UUID: {}", uuid)),
                            Err(e) => app.log_message(format!("Could not get Root Key UUID: {}", e)),
                        }
                    }
                } else {
                    app.status_message = "Root Key: Not connected.".to_string();
                    app.log_message("Root Key: Not connected or found.");
                }
                app.usb_key_manager = Some(uk);
            }
            Err(e) => {
                app.status_message = format!("Failed to access Root Key: {}", e);
                app.log_message(format!("Error initializing Root Key manager: {}", e));
            }
        }
        app.initialize_main_storage_manager(); // The big shaboom start
        app
    }
}

impl MyApp {
    fn log_message(&mut self, message: impl Into<String>) {
        let msg = message.into();
        println!("LOG: {}", msg); // Console log print
        self.log_messages.push(msg);
        if self.log_messages.len() > 200 { // Log length
            self.log_messages.remove(0);
        }
    }

    fn initialize_main_storage_manager(&mut self) {
        let path = self.main_storage_path_input.clone();
        // TODO cloud storage selection and config
        let mut ms = forest_lib::main_storage::MainStorage::new(
            path,
            forest_lib::main_storage::StorageType::Local, // ph
            None, // surprise, even more cloud shit, no cloud config for local
        );
        match ms.initialize() {
            Ok(_) => {
                self.log_message(format!("Main Storage initialized at '{}'", self.main_storage_path_input));
                self.main_storage_manager = Some(ms);
            }
            Err(e) => {
                self.log_message(format!("Failed to initialize Main Storage: {}", e));
                self.status_message = format!("Main Storage Error: {}", e);
                self.main_storage_manager = None;
            }
        }
    }

    fn handle_initialize_usb(&mut self) {
        if let Some(uk) = self.usb_key_manager.as_mut() {
            if uk.is_key_initialized() {
                self.log_message("Root Key is already initialized.");
                self.status_message = "Root Key already initialized.".to_string();
                self.home_action_state = HomeActionState::Idle;
                return;
            }

            let forest_s = self.init_forest_secret.trim();
            if forest_s.is_empty() {
                self.log_message("Forest Secret cannot be empty for initialization.");
                self.status_message = "Forest Secret is required.".to_string();
                return;
            }

            // Use Option::None if string is empty for optional secrets
            let burn_s = Some(self.init_burn_secret.trim()).filter(|s| !s.is_empty());
            let ember_s = Some(self.init_ember_secret.trim()).filter(|s| !s.is_empty());
            let smoke_s = Some(self.init_smoke_secret.trim()).filter(|s| !s.is_empty());
            let seed_s = Some(self.init_seed_secret.trim()).filter(|s| !s.is_empty());

            match uk.initialize(forest_s, burn_s, ember_s, smoke_s, seed_s) {
                Ok(_) => {
                    self.log_message("Root Key initialized successfully!".to_string());
                    self.status_message = "Root Key Initialized.".to_string();
                    if let Ok(uuid) = uk.get_uuid() { // get_uuid might need &mut self
                        self.log_message(format!("New Root Key UUID: {}", uuid));
                    }
                }
                Err(e) => {
                    self.log_message(format!("Root Key initialization failed: {}", e));
                    self.status_message = format!("Initialization Error: {}", e);
                }
            }
        } else {
            self.log_message("Root Key manager not available.");
            self.status_message = "Root Key Error: Not connected/available.".to_string();
        }
        // Clear secrets from input fields after attempt
        self.init_forest_secret.clear();
        self.init_burn_secret.clear();
        self.init_ember_secret.clear();
        self.init_smoke_secret.clear();
        self.init_seed_secret.clear();
        self.home_action_state = HomeActionState::Idle;
    }

    fn handle_authenticate_usb(&mut self) {
        if let Some(uk) = self.usb_key_manager.as_mut() {
            if !uk.is_key_initialized() {
                self.log_message("Root Key is not initialized. Cannot authenticate.");
                self.status_message = "Root Key not initialized.".to_string();
                self.home_action_state = HomeActionState::Idle;
                return;
            }
            let key_input = self.auth_key_input.trim();
            if key_input.is_empty() {
                self.log_message("Authentication key cannot be empty.");
                self.status_message = "Authentication key required.".to_string();
                return;
            }

            let auth_outcome = uk.authenticate(key_input);
            self.log_message(format!("Authentication attempt outcome: {:?}", auth_outcome));

            match auth_outcome {
                forest_lib::usb_key::AuthOutcome::Success => {
                    self.status_message = "Authenticated successfully!".to_string();
                    match uk.get_decrypted_main_storage_dek() {
                        Ok(dek) => {
                            self.main_storage_dek = dek;
                            self.log_message("Main Storage DEK retrieved.");
                        }
                        Err(e) => {
                            self.log_message(format!("Failed to get Main Storage DEK: {}", e));
                            self.status_message = format!("Auth Error: {}", e);
                            // Invalidate auth if DEK retrieval fails
                            // This depends on how UsbKey manages its internal `is_auth` state
                        }
                    }
                }
                forest_lib::usb_key::AuthOutcome::SuccessSeedTriggered => {
                    self.status_message = "Authenticated (Seed Triggered)!".to_string();
                    // TODO handle DEK retrieval normally
                }
                forest_lib::usb_key::AuthOutcome::BurnTriggered => {
                    self.status_message = "BURN KEY ACTIVATED!".to_string();
                    self.home_action_state = HomeActionState::ShowingBurnConfirmPopup;
                }
                forest_lib::usb_key::AuthOutcome::EmberTriggered => {
                    self.status_message = "Ember Key: One-time view authenticated.".to_string();
                    // TODO handle DEK retrieval then potentially clear auth/DEK
                }
                forest_lib::usb_key::AuthOutcome::SmokeTriggered => {
                    self.status_message = "Smoke Key: Decoy environment active.".to_string();
                    // TODO idk if UI is reflecting decoy state
                    self.main_storage_dek.clear();
                }
                forest_lib::usb_key::AuthOutcome::Failed(e) => {
                    self.status_message = format!("Authentication Failed: {}", e);
                    self.main_storage_dek.clear();
                }
            }
        } else {
            self.log_message("Root Key manager not available for authentication.");
            self.status_message = "Root Key Error: Not connected/available.".to_string();
        }
        self.auth_key_input.clear();
        if self.home_action_state != HomeActionState::ShowingBurnConfirmPopup {
             self.home_action_state = HomeActionState::Idle;
        }
    }

    fn perform_burn_action(&mut self) {
        self.log_message("Burn action confirmed by user. Proceeding with erasure...");
        let mut all_erased = true;
        if let Some(uk) = self.usb_key_manager.as_mut() {
            match uk.secure_erase_usb_data() {
                Ok(_) => self.log_message("Root Key data erased successfully."),
                Err(e) => {
                    self.log_message(format!("Failed to erase USB key data: {}", e));
                    all_erased = false;
                }
            }
        }
        if let Some(ms) = self.main_storage_manager.as_mut() {
            match ms.secure_erase_all_data() {
                Ok(_) => self.log_message("Main Storage data erased successfully."),
                Err(e) => {
                    self.log_message(format!("Failed to erase Main Storage data: {}", e));
                    all_erased = false;
                }
            }
        }
        self.main_storage_dek.clear(); // Clear DEK from memory
        self.status_message = if all_erased { "SYSTEM DATA ERASED." } else { "DATA ERASURE FAILED OR PARTIAL." };
        // Reset relevant app state
    }


    fn handle_shard_file(&mut self) {
        if self.main_storage_dek.is_empty() {
            self.log_message("Not authenticated or DEK not available. Cannot shard file.");
            self.status_message = "Authentication required for sharding.".to_string();
            return;
        }
        if self.file_to_shard_path.is_empty() {
            self.log_message("No file selected for sharding.");
            self.status_message = "Select a file to shard.".to_string();
            return;
        }
        if self.usb_key_manager.is_none() || self.main_storage_manager.is_none() {
            self.log_message("Root Key or Main Storage not ready.");
            return;
        }

        let file_path = PathBuf::from(self.file_to_shard_path.clone());
        let file_id = uuid::Uuid::new_v4().to_string(); // Generate unique ID for this sharded file

        self.log_message(format!("Sharding file: {:?} with ID: {}", file_path, file_id));

        match forest_lib::sharding::shard_file(&file_path, &self.main_storage_dek, &file_id) {
            Ok((manifest, shards)) => {
                self.log_message(format!("File sharded successfully into {} shards. Manifest ID: {}", shards.len(), manifest.file_id));

                let uk = self.usb_key_manager.as_mut().unwrap();
                let ms = self.main_storage_manager.as_ref().unwrap();
                let mut success = true;

                for shard in shards {
                    if shard.shard_index == forest_lib::config::USB_KEY_SHARD_INDEX as i32 { // Assuming USB_KEY_SHARD_INDEX is defined in your lib's config
                        if let Err(e) = uk.store_usb_shard(shard.clone()) { // Clone if original needed later
                            self.log_message(format!("Failed to store Root Key shard (idx {}): {}", shard.shard_index, e));
                            success = false; break;
                        }
                         self.log_message(format!("Stored shard idx {} to Root Key.", shard.shard_index));
                    } else {
                        if let Err(e) = ms.store_shard(shard.shard_index, &shard) {
                            self.log_message(format!("Failed to store shard idx {} to Main Storage: {}", shard.shard_index, e));
                            success = false; break;
                        }
                        self.log_message(format!("Stored shard idx {} to Main Storage.", shard.shard_index));
                    }
                }

                if success {
                    // Store manifest under main_storage_dek for manifest encryption
                    match forest_lib::sharding::store_manifest(ms, &manifest, &self.main_storage_dek) {
                        Ok(_) => self.log_message(format!("Manifest {} stored successfully.", manifest.file_id)),
                        Err(e) => {
                            self.log_message(format!("Failed to store manifest {}: {}", manifest.file_id, e));
                            success = false;
                        }
                    }
                }

                if success {
                    self.status_message = format!("File '{}' sharded. Manifest ID: {}", file_path.file_name().unwrap_or_default().to_string_lossy(), manifest.file_id);
                } else {
                    self.status_message = "Error during shard/manifest storage.".to_string();
                    // TODO cleanup partially stored shards/manifest if theyre there
                }
            }
            Err(e) => {
                self.log_message(format!("Failed to shard file: {}", e));
                self.status_message = format!("Sharding Error: {}", e);
            }
        }
    }

    fn handle_reconstruct_file(&mut self) {
        if self.main_storage_dek.is_empty() {
            self.log_message("Not authenticated or DEK not available. Cannot reconstruct file.");
             self.status_message = "Authentication required for reconstruction.".to_string();
            return;
        }
        if self.manifest_file_id_for_reconstruction.is_empty() {
            self.log_message("No manifest ID provided for reconstruction.");
            self.status_message = "Enter Manifest ID to reconstruct.".to_string();
            return;
        }
        if self.reconstructed_file_output_path.is_empty() {
            self.log_message("No output path specified for reconstructed file.");
            self.status_message = "Specify output path for reconstruction.".to_string();
            return;
        }
         if self.usb_key_manager.is_none() || self.main_storage_manager.is_none() {
            self.log_message("USB Key or Main Storage not ready.");
            return;
        }

        let output_path = PathBuf::from(self.reconstructed_file_output_path.clone());
        let manifest_id = self.manifest_file_id_for_reconstruction.trim();
        let ms = self.main_storage_manager.as_ref().unwrap();
        let uk = self.usb_key_manager.as_ref().unwrap();

        self.log_message(format!("Reconstructing from manifest ID: {} to {:?}", manifest_id, output_path));

        match forest_lib::sharding::retrieve_manifest(ms, manifest_id, &self.main_storage_dek) {
            Ok(manifest) => {
                self.log_message(format!("Manifest '{}' retrieved. Original file: {}", manifest.file_id, manifest.original_filename));
                match forest_lib::sharding::reconstruct_file(&manifest, &self.main_storage_dek, &output_path, uk, ms) {
                    Ok(_) => {
                        self.log_message(format!("File '{}' reconstructed successfully to {:?}", manifest.original_filename, output_path));
                        self.status_message = format!("File '{}' reconstructed.", manifest.original_filename);
                    }
                    Err(e) => {
                        self.log_message(format!("Failed to reconstruct file: {}", e));
                        self.status_message = format!("Reconstruction Error: {}", e);
                    }
                }
            }
            Err(e) => {
                self.log_message(format!("Failed to retrieve manifest {}: {}", manifest_id, e));
                self.status_message = format!("Manifest Error: {}", e);
            }
        }
    }
}


impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Update status based on USB key manager if it exists
        let (usb_init_status_str, usb_auth_status_str) = if let Some(uk) = &self.usb_key_manager {
            (
                if uk.is_key_initialized() { "Root Key Initialized" } else { "Root Key NOT Initialized" },
                if uk.is_auth { "Authenticated" } else { "NOT Authenticated" } // Assuming UsbKey has an `is_auth` public field
            )
        } else {
            ("USB Manager Error", "N/A")
        };


        if self.home_action_state == HomeActionState::ShowingInitializePopup {
            egui::Window::new("Initialize Root Key")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.label("Enter secrets for USB key initialization. Leave optional fields blank if not used.");
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.label("Forest Secret (Required):");
                        ui.add(egui::TextEdit::singleline(&mut self.init_forest_secret).password(true));
                    });
                    ui.horizontal(|ui| {
                        ui.label("Burn Secret (Optional):");
                        ui.add(egui::TextEdit::singleline(&mut self.init_burn_secret).password(true));
                    });
                    ui.horizontal(|ui| {
                        ui.label("Ember Secret (Optional):");
                        ui.add(egui::TextEdit::singleline(&mut self.init_ember_secret).password(true));
                    });
                    ui.horizontal(|ui| {
                        ui.label("Smoke Secret (Optional):");
                        ui.add(egui::TextEdit::singleline(&mut self.init_smoke_secret).password(true));
                    });
                    ui.horizontal(|ui| {
                        ui.label("Seed Secret (Optional):");
                        ui.add(egui::TextEdit::singleline(&mut self.init_seed_secret).password(true));
                    });
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("Initialize").clicked() {
                            self.handle_initialize_usb();
                        }
                        if ui.button("Cancel").clicked() {
                            self.home_action_state = HomeActionState::Idle;
                        }
                    });
                });
        }

        if self.home_action_state == HomeActionState::ShowingAuthPopup {
            egui::Window::new("Authenticate Root Key")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.label("Enter your key (e.g., Forest Secret, Burn Secret):");
                     ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.label("Key:");
                        ui.add(egui::TextEdit::singleline(&mut self.auth_key_input).password(true).desired_width(200.0));
                    });
                     ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("Authenticate").clicked() {
                            self.handle_authenticate_usb();
                        }
                        if ui.button("Cancel").clicked() {
                            self.home_action_state = HomeActionState::Idle;
                        }
                    });
                });
        }

        // TODO Add setting to skip warning during setup
        if self.home_action_state == HomeActionState::ShowingBurnConfirmPopup {
            egui::Window::new("⚠️ BURN KEY ACTIVATED - CONFIRMATION ⚠️")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.label(egui::RichText::new("EXTREME WARNING!").color(egui::Color32::RED).strong());
                    ui.label("You have entered a BURN KEY. This action is IRREVERSIBLE and will securely erase all data on the USB Key and potentially linked Main Storage.");
                    ui.label("Are you absolutely sure you want to proceed with data destruction?");
                    ui.add_space(20.0);
                    ui.horizontal(|ui| {
                        if ui.button(egui::RichText::new("YES, DESTROY ALL DATA").color(egui::Color32::RED).strong()).clicked() {
                            self.perform_burn_action();
                            self.home_action_state = HomeActionState::Idle;
                        }
                        if ui.button("NO, Cancel").clicked() {
                            self.log_message("Burn action cancelled by user.");
                            self.status_message = "Burn action cancelled.".to_string();
                            self.home_action_state = HomeActionState::Idle;
                        }
                    });
                });
        }


        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status_message);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(format!("USB: {} | Auth: {}", usb_init_status_str, usb_auth_status_str));
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, Tab::Home, "Home");
                ui.selectable_value(&mut self.active_tab, Tab::KeyManagement, "Key Management");
                ui.selectable_value(&mut self.active_tab, Tab::DataOperations, "Data Operations");
                ui.selectable_value(&mut self.active_tab, Tab::Settings, "Settings");
                ui.selectable_value(&mut self.active_tab, Tab::Logs, "Logs");
            });
            ui.separator();

            match self.active_tab {
                Tab::Home => {
                    ui.heading("Forest - Home");
                    ui.add_space(10.0);
                    if ui.button("Initialize Root Key").clicked() {
                        self.home_action_state = HomeActionState::ShowingInitializePopup;
                    }
                    if ui.button("Authenticate with Root Key").clicked() {
                        self.home_action_state = HomeActionState::ShowingAuthPopup;
                    }
                }
                Tab::KeyManagement => {
                    ui.heading("Key Management");
                    ui.label("Note: Secrets for initialization are entered via the 'Initialize Root Key' popup on the Home tab.");
                    ui.label("To use Burn/Ember/Smoke/Seed keys after initialization, use the 'Authenticate with Root Key' option on the Home tab with the respective secret.");
                    ui.add_space(10.0);
                    if ui.button("Generate Example Strong Secret").clicked() {
                        match forest_lib::crypto::generate_random_bytes(24) { // 24 bytes/192 bits
                            Ok(bytes) => {
                                let hex_secret = hex::encode(bytes);
                                self.log_message(format!("Generated example secret (hex): {}", hex_secret));
                                self.status_message = "Example secret generated (see logs). Copy and save securely.".to_string();
                                if let Err(e) = ClipboardContext::new().unwrap().set_contents(hex_secret.clone()) {
                                    self.log_message(format!("Error copying to clipboard: {}", e));
                                    self.status_message = "Error copying to clipboard.".to_string();
                                }
                                ui.output_mut(|o| o.copied_text = hex_secret);
                            }
                            Err(e) => self.log_message(format!("Failed to generate random secret: {}", e)),
                        }
                    }
                }
                Tab::DataOperations => {
                    ui.heading("Data Operations");
                     ui.add_space(10.0);
                    ui.label("Ensure you are authenticated with your Root Key before sharding or reconstructing.");
                    ui.add_space(10.0);

                    ui.group(|ui| {
                        ui.heading("Shard File");
                        ui.horizontal(|ui| {
                            ui.label("File to Shard:");
                            ui.text_edit_singleline(&mut self.file_to_shard_path).desired_width(300.0);
                            if ui.button("Browse...").clicked() {
                                if let Some(path) = rfd::FileDialog::new().pick_file() {
                                    self.file_to_shard_path = path.display().to_string();
                                }
                            }
                        });
                        if ui.button("Shard Selected File").clicked() {
                            self.handle_shard_file();
                        }
                    });
                    ui.add_space(10.0);
                    ui.group(|ui| {
                        ui.heading("Reconstruct File");
                         ui.horizontal(|ui| {
                            ui.label("Manifest ID:");
                            ui.text_edit_singleline(&mut self.manifest_file_id_for_reconstruction);
                        });
                        ui.horizontal(|ui| {
                            ui.label("Output Path for Reconstructed File:");
                            ui.text_edit_singleline(&mut self.reconstructed_file_output_path).desired_width(300.0);
                             if ui.button("Browse...").clicked() {
                                if let Some(path) = rfd::FileDialog::new().save_file() {
                                    self.reconstructed_file_output_path = path.display().to_string();
                                }
                            }
                        });
                        if ui.button("Reconstruct from Manifest").clicked() {
                            self.handle_reconstruct_file();
                        }
                    });
                }
                Tab::Settings => {
                    ui.heading("Settings");
                    ui.group(|ui| {
                        ui.label("Main Storage Configuration:");
                        // TODO add cloud selection, for now, only local path
                        ui.horizontal(|ui| {
                            ui.label("Local Storage Path:");
                            ui.text_edit_singleline(&mut self.main_storage_path_input);
                        });
                        if ui.button("Apply & Re-initialize Main Storage").clicked() {
                            self.initialize_main_storage_manager();
                        }
                    });
                    // TODO add default shard sizes, crypto parameters
                }
                Tab::Logs => {
                    ui.heading("Operation Logs");
                    ui.horizontal(|ui| {
                        if ui.button("Clear Logs").clicked() {
                            self.log_messages.clear();
                            self.log_message("Logs cleared.");
                        }
                        // Future: Save logs to file
                    });
                    ui.add_space(5.0);
                    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                        for message in self.log_messages.iter().rev() { // Show newest first
                            ui.label(message);
                        }
                    });
                }
            }
        });
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([800.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Forest",
        options,
        Box::new(|_cc| Box::<MyApp>::default()),
    )
}
