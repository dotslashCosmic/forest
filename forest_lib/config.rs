// Author: dotslashCosmic
// Shamir's Secret Sharing
pub const REQUIRED_SHARDS: usize = 3;

// Default path for local storage, platform-specific
#[cfg(target_os = "windows")]
pub const DEFAULT_MAIN_STORAGE_PATH: &str = "C:\\ForestSecureStorage\\main_storage";
#[cfg(target_os = "macos")]
pub const DEFAULT_MAIN_STORAGE_PATH: &str = "/Users/Shared/ForestSecureStorage/main_storage";
#[cfg(target_os = "linux")]
pub const DEFAULT_MAIN_STORAGE_PATH: &str = "/var/lib/forest_secure_storage/main_storage";
#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub const DEFAULT_MAIN_STORAGE_PATH: &str = "./forest_main_storage"; // Fallback for other OS

// Cryptographic Parameters
pub const KEK_LENGTH: usize = 32; // Key Encryption Key length in bytes (e.g., for XChaCha20-Poly1305)
pub const DEK_LENGTH: usize = 32; // Data Encryption Key length in bytes (for XChaCha20-Poly1305)
pub const SALT_LENGTH: usize = 16; // Salt length in bytes for key derivation

// Argon2id Parameters (for key derivation from passwords)
pub const ARGON2_ITERATIONS: u32 = 3; // Number of iterations
pub const ARGON2_MEMORY_KB: usize = 65536; // Memory cost in kilobytes (64MB)
pub const ARGON2_PARALLELISM: u32 = 1; // Number of parallel threads

// Secure Erasure Parameters
pub const SECURE_ERASE_PASSES: u32 = 3;

// MainStorage configuration
pub const MIN_SHARDS_STORAGE: usize = 4; // Minimum number of shards for MainStorage
pub const MAX_SHARD_SIZE_BYTES: usize = 64 * 1024 * 1024; // 64 MB

// Root Key configuration
// If REQUIRED_SHARDS is the total number of shards created by SSS, and one is on USB, this might be `REQUIRED_SHARDS -1`.
pub const USB_KEY_SHARD_INDEX: usize = REQUIRED_SHARDS -1;
