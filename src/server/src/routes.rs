use crate::StorageState;
use crate::crypto::SecureServer;
use crate::storage::ClientData;
use crate::wordlist;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use once_cell::sync::Lazy;
use rand::RngCore;
use rocket::http::Status;
use rocket::post;
use rocket::{State, serde::json::Json};
use shared::{
    EncryptedRequest, EncryptedResponse, FullDecryptCredentials, GetFileWordRequest,
    GetFileWordResponse, RegisterClientRequest, RegisterClientResponse, RetrieveKeyRequest,
    UpdateCredentialsRequest, UpdateCredentialsResponse,
};
use std::sync::Mutex;
use uuid::Uuid;

static CRYPTO: Lazy<Mutex<SecureServer>> =
    Lazy::new(|| Mutex::new(SecureServer::new().expect("Failed to load server keys")));

// ============================================================================
// Routes
// ============================================================================

#[post("/register", data = "<payload>")]
pub async fn register_client(
    storage: &State<StorageState>,
    payload: Json<EncryptedRequest>,
) -> Result<Json<EncryptedResponse>, Status> {
    let (req, shared_secret): (RegisterClientRequest, _) = {
        let crypto = CRYPTO.lock().unwrap();

        crypto
            .decrypt_request(payload.into_inner())
            .expect("Failed to decrypt register request")
    };

    let client_id = Uuid::new_v4();

    let mut store = storage.write().await;
    store.add_client(ClientData {
        client_id,
        root_word: req.root_word.clone(),
        key_wrapper_salt: req.key_wrapper_salt,
        salt_word_global: req.salt_word_global,
        payment_received: false,
    });
    let _ = store.save_to_disk();

    println!("✅ New client: {}", client_id);

    let resp = RegisterClientResponse { client_id };

    let crypto = CRYPTO.lock().unwrap();
    let enc_resp = crypto.encrypt_response(&resp, shared_secret).unwrap();

    Ok(Json(enc_resp))
}

#[post("/decrypt_full", data = "<payload>")]
pub async fn get_full_decrypt_credentials(
    storage: &State<StorageState>,
    payload: Json<EncryptedRequest>,
) -> Result<Json<EncryptedResponse>, Status> {
    let (req, shared_secret) = {
        let crypto = CRYPTO.lock().unwrap();

        match crypto.decrypt_request::<RetrieveKeyRequest>(payload.into_inner()) {
            Ok(res) => res,
            Err(_) => return Err(Status::BadRequest),
        }
    };
    let client_id = Uuid::parse_str(&req.client_id).map_err(|_| Status::BadRequest)?;

    let store = storage.read().await;

    let client = store.get_client(&client_id).ok_or(Status::NotFound)?;

    let mut proof_pt = [0u8; 32];

    rand::rngs::OsRng.fill_bytes(&mut proof_pt);

    let mut key_bytes = [0u8; 32];
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|_| Status::InternalServerError)?;
    let alg = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    alg.hash_password_into(
        client.root_word.as_bytes(),
        &client.key_wrapper_salt,
        &mut key_bytes,
    )
    .map_err(|_| Status::InternalServerError)?;

    let cipher = XChaCha20Poly1305::new((&key_bytes).into());
    let mut nonce_bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let mut proof_ct = cipher
        .encrypt(nonce, proof_pt.as_ref())
        .map_err(|_| Status::InternalServerError)?;

    let mut proof_with_nonce = nonce_bytes.to_vec();
    proof_with_nonce.append(&mut proof_ct);

    let resp = FullDecryptCredentials {
        root_word: client.root_word.clone(),
        key_wrapper_salt: client.key_wrapper_salt,
        proof_plaintext: proof_pt,
        proof_ciphertext: proof_with_nonce,
    };

    let crypto = CRYPTO.lock().unwrap();
    let enc_resp = crypto
        .encrypt_response(&resp, shared_secret)
        .map_err(|_| Status::InternalServerError)?;

    println!("🔓 Root credentials sent to: {}", client_id);

    Ok(Json(enc_resp))
}

#[post("/decrypt_file", data = "<payload>")]
pub async fn get_file_word(
    storage: &State<StorageState>,
    payload: Json<EncryptedRequest>,
) -> Result<Json<EncryptedResponse>, Status> {
    let (req, shared_secret) = {
        let crypto = CRYPTO.lock().unwrap();

        match crypto.decrypt_request::<GetFileWordRequest>(payload.into_inner()) {
            Ok(res) => res,
            Err(_) => return Err(Status::BadRequest),
        }
    };

    let cid = Uuid::parse_str(&req.client_id).map_err(|_| Status::BadRequest)?;
    let store = storage.read().await;

    let client = store.get_client(&cid).ok_or(Status::NotFound)?;

    let word = wordlist::generate_word_for_path(&req.file_path, &client.salt_word_global)
        .map_err(|_| Status::InternalServerError)?;

    println!("Word '{}' sent to {}", word, cid);

    let resp = GetFileWordResponse {
        word,
        file_path: req.file_path,
    };

    let crypto = CRYPTO.lock().unwrap();
    let enc_resp = crypto
        .encrypt_response(&resp, shared_secret)
        .map_err(|_| Status::InternalServerError)?;

    Ok(Json(enc_resp))
}

#[post("/update_credentials", data = "<payload>")]
pub async fn update_credentials(
    storage: &State<StorageState>,
    payload: Json<EncryptedRequest>,
) -> Result<Json<EncryptedResponse>, Status> {
    let (req, shared_secret) = {
        let crypto = CRYPTO.lock().unwrap();

        match crypto.decrypt_request::<UpdateCredentialsRequest>(payload.into_inner()) {
            Ok(res) => res,
            Err(_) => return Err(Status::BadRequest),
        }
    };

    let client_id = Uuid::parse_str(&req.client_id).map_err(|_| Status::BadRequest)?;

    let mut store = storage.write().await;
    let client = store.get_client_mut(&client_id).ok_or(Status::NotFound)?;

    println!("🔑 Credential update for: {}", client_id);

    client.root_word = req.new_root_word;
    client.key_wrapper_salt = req.new_key_wrapper_salt;

    let _ = store.save_to_disk();

    let resp = UpdateCredentialsResponse { success: true };

    let crypto = CRYPTO.lock().unwrap();
    let enc_resp = crypto
        .encrypt_response(&resp, shared_secret)
        .map_err(|_| Status::InternalServerError)?;

    Ok(Json(enc_resp))
}
