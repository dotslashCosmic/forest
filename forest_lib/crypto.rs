// Author: dotslashCosmic
use crate::config;
use anyhow::{anyhow, Result, Context};
use orion::aead::xchacha20poly1305;
use argon2::{Argon2, Params, Version};
use sha3::{Digest, Sha3_512};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

pub use orion::aead::xchacha20poly1305::XNONCE_LEN;

pub fn generate_random_bytes(length: usize) -> Result<Vec<u8>> {
    if length == 0 {
        return Ok(Vec::new()); // case underflow should be fine
    }
    let mut random_bytes = vec![0u8; length];
    OsRng
        .try_fill_bytes(&mut random_bytes)
        .map_err(|e| anyhow!("Failed to generate random bytes: {}", e))?;
    Ok(random_bytes)
}

// Argon2id key derivation
pub fn derive_key_argon2(
    password: &str,
    salt: &[u8],
    derived_key_len: usize,
) -> Result<Vec<u8>> {

    if salt.len() < config::SALT_LENGTH {
        return Err(anyhow!(
            "Argon2 salt size is {} bytes, which is less than the recommended 16 bytes.",
            salt.len()
        ));
    }
    if derived_key_len == 0 {
        return Err(anyhow!("Derived key length cannot be zero."));
    }

    let mut derived_key = vec![0u8; derived_key_len];

    let iterations = config::ARGON2_ITERATIONS;
    let memory_cost = config::ARGON2_MEMORY_KB;
    let parallelism = config::ARGON2_PARALLELISM;

    let params = Params::new(
        memory_cost as u32,
        iterations,
        parallelism,
        Some(derived_key_len)
    )
    .map_err(|e| anyhow!("Failed to create Argon2 parameters: {}", e))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        params
    );

    argon2.hash_password_into(password.as_bytes(), salt, &mut derived_key)
        .map_err(|e| anyhow!("Argon2id key derivation failed: {}", e))?;

    Ok(derived_key)
}

// XChaCha20-Poly1305
pub fn encrypt_xchacha20_poly1305(
    plaintext: &[u8],
    key: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>)> { // Returns (ciphertext_with_tag, nonce)
    if key.len() != config::DEK_LENGTH { // Assuming DEK_LENGTH for XChaCha20 keys
        return Err(anyhow!(
            "XChaCha20-Poly1305 requires a {}-byte key. Provided key length: {}",
            config::DEK_LENGTH, key.len()
        ));
    }
    let key_obj = xchacha20poly1305::SecretKey::from_slice(key)
        .map_err(|e| anyhow!("Invalid key for XChaCha20-Poly1305: {}. Key length: {}", e, key.len()))?;

    let nonce_bytes = generate_random_bytes(xchacha20poly1305::XNONCE_LEN)?; // 24 byte nonce
    let nonce = xchacha20poly1305::Nonce::from_slice(&nonce_bytes)
        .map_err(|e| anyhow!("Failed to create XChaCha20 nonce: {}", e))?;

    let mut ciphertext_and_tag = vec![0u8; plaintext.len() + xchacha20poly1305::TAG_SIZE];

    xchacha20poly1305::seal(&key_obj, &nonce, plaintext, None /* associated_data */, &mut ciphertext_and_tag)
         .map_err(|e| anyhow!("XChaCha20-Poly1305 encryption failed: {}", e))?;

    Ok((ciphertext_and_tag, nonce_bytes))
}

pub fn decrypt_xchacha20_poly1305(
    ciphertext_with_tag: &[u8],
    key: &[u8],
    nonce_bytes: &[u8],
    associated_data: Option<&[u8]>, // AEAD check
) -> Result<Vec<u8>> {
    if key.len() != config::DEK_LENGTH {
        return Err(anyhow!(
            "XChaCha20-Poly1305 requires a {}-byte key. Provided key length: {}",
            config::DEK_LENGTH, key.len()
        ));
    }
    if nonce_bytes.len() != xchacha20poly1305::XNONCE_LEN {
        return Err(anyhow!("XChaCha20-Poly1305 requires a {}-byte nonce. Provided nonce length: {}", 
            xchacha20poly1305::XNONCE_LEN, nonce_bytes.len()));
    }
    if ciphertext_with_tag.len() < xchacha20poly1305::TAG_SIZE {
        return Err(anyhow!("Ciphertext is too short to contain a tag. Minimum length: {}, Provided: {}", 
            xchacha20poly1305::TAG_SIZE, ciphertext_with_tag.len()));
    }

    let key_obj = xchacha20poly1305::SecretKey::from_slice(key)
        .map_err(|e| anyhow!("Invalid key for XChaCha20-Poly1305 decryption: {}", e))?;
    let nonce = xchacha20poly1305::Nonce::from_slice(nonce_bytes)
        .map_err(|e| anyhow!("Invalid nonce for XChaCha20 decryption: {}", e))?;

    let mut plaintext = vec![0u8; ciphertext_with_tag.len() - xchacha20poly1305::TAG_SIZE];

    xchacha20poly1305::open(&key_obj, &nonce, ciphertext_with_tag, None /* associated_data */, &mut plaintext)
        .map_err(|e| anyhow!("XChaCha20-Poly1305 decryption/authentication failed (tag mismatch or other error): {}", e))?;

    Ok(plaintext)
}

pub fn secure_erase(data: &mut Vec<u8>) {
    data.zeroize();
    data.clear();
    data.shrink_to_fit();
}

pub fn hash_sha3_512(data: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    Ok(hasher.finalize().to_vec())
}

pub fn split_secret_sss(secret: &[u8], n_shares_total: u8, k_shares_threshold: u8) -> Result<Vec<Vec<u8>>> {
    if k_shares_threshold == 0 || n_shares_total == 0 {
        return Err(anyhow!("Number of shares (n) and threshold (k) must be greater than zero."));
    }
    if k_shares_threshold > n_shares_total {
        return Err(anyhow!("Threshold (k) cannot be greater than the total number of shares (n)."));
    }
    if secret.is_empty() {
        return Err(anyhow!("Secret for SSS split cannot be empty."));
    }
    
    shamirsecretsharing::split_secret(k_shares_threshold, n_shares_total, secret, None) 
        .map_err(|e| anyhow!("Shamir's Secret Sharing split failed: {:?}", e))
}

pub fn reconstruct_secret_sss(shares: &[Vec<u8>]) -> Result<Vec<u8>> {
    if shares.is_empty() {
        return Err(anyhow!("No shares provided for SSS reconstruction."));
    }
    let share_slices: Vec<&[u8]> = shares.iter().map(|s_vec| s_vec.as_slice()).collect();
    shamirsecretsharing::reconstruct_secret(&share_slices)
        .map_err(|e| anyhow!("Shamir's Secret Sharing reconstruction failed: {:?}. Ensure enough unique shares are provided.", e))
}
