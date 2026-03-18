use anyhow::{Result, anyhow};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use libcrux_ml_dsa::ml_dsa_87;
use libcrux_ml_kem::mlkem1024;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use shared::{EncryptedRequest, EncryptedResponse, SignedPayload};
use std::time::{SystemTime, UNIX_EPOCH};

// Bundled Server Private Keys
const SERVER_KEM_SK: &[u8] = include_bytes!("../../../data/server_kem.priv");
const SERVER_DSA_SK: &[u8] = include_bytes!("../../../data/server_dsa.priv");
const MAX_TIMESTAMP_DRIFT_SECS: u64 = 300;

pub struct SecureServer {
    kem_sk: mlkem1024::MlKem1024PrivateKey,
    dsa_sk: ml_dsa_87::MLDSA87SigningKey,
}

impl SecureServer {
    pub fn new() -> Result<Self> {
        let client_kem_bytes: [u8; 3168] = SERVER_KEM_SK
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid Client KEM key size"))?;
        let kem_sk = mlkem1024::MlKem1024PrivateKey::from(client_kem_bytes);

        let client_dsa_bytes: [u8; 4896] = SERVER_DSA_SK
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid Client DSA key size"))?;
        let dsa_sk = ml_dsa_87::MLDSA87SigningKey::new(client_dsa_bytes);

        Ok(Self { kem_sk, dsa_sk })
    }

    pub fn decrypt_request<T: for<'a> Deserialize<'a>>(
        &self,
        req: EncryptedRequest,
    ) -> Result<(T, [u8; 32])> {
        let mut ct_arr = [0u8; 1568];
        if req.kem_ct.len() != 1568 {
            return Err(anyhow!("Invalid ciphertext length"));
        }
        ct_arr.copy_from_slice(&req.kem_ct);

        let kem_ct = mlkem1024::MlKem1024Ciphertext::from(&ct_arr);
        let shared_secret = mlkem1024::decapsulate(&self.kem_sk, &kem_ct);

        // Derive Key
        let hk = Hkdf::<Sha3_256>::new(None, &shared_secret);
        let mut sym_key = [0u8; 32];
        hk.expand(b"qrypto-session-key", &mut sym_key)
            .map_err(|e| anyhow::anyhow!("Failed to generate sym key: {}", e))?;

        // Decrypt Payload
        let cipher = XChaCha20Poly1305::new(&sym_key.into());
        let nonce = XNonce::from_slice(&req.nonce);
        let plaintext = cipher
            .decrypt(nonce, req.payload_ct.as_ref())
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        // Verify Signature
        let signed_payload: SignedPayload = serde_json::from_slice(&plaintext)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("Time Error: {}", e))?
            .as_secs();

        let timestamp = signed_payload.timestamp;
        let drift = now.abs_diff(timestamp);

        if drift > MAX_TIMESTAMP_DRIFT_SECS {
            return Err(anyhow::anyhow!(
                "Request timestamp too old or too far in future (drift: {}s, max: {}s",
                drift,
                MAX_TIMESTAMP_DRIFT_SECS
            ));
        }

        let client_vk_bytes: [u8; 2592] = req
            .client_vk
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid Client Verification key"))?;

        let client_vk = ml_dsa_87::MLDSA87VerificationKey::new(client_vk_bytes);

        let mut sig_arr = [0u8; 4627];
        if signed_payload.signature.len() != 4627 {
            return Err(anyhow!("Invalid sig len"));
        }
        sig_arr.copy_from_slice(&signed_payload.signature);
        let sig = ml_dsa_87::MLDSA87Signature::new(sig_arr);

        let mut to_verify = signed_payload.data.clone();
        to_verify.extend_from_slice(&timestamp.to_le_bytes());

        ml_dsa_87::verify(&client_vk, &to_verify, b"QRYPTO-CLIENT-REQUEST", &sig)
            .map_err(|_| anyhow!("Invalid Client Signature"))?;

        let data: T = serde_json::from_slice(&signed_payload.data)?;

        Ok((data, shared_secret))
    }

    pub fn encrypt_response<T: Serialize>(
        &self,
        data: &T,
        shared_secret: [u8; 32],
    ) -> Result<EncryptedResponse> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("Time error: {}", e))?
            .as_secs();

        // Sign
        let data_bytes = serde_json::to_vec(data)?;

        let mut to_sign = data_bytes.clone();
        to_sign.extend_from_slice(&timestamp.to_le_bytes());

        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signature = ml_dsa_87::sign(&self.dsa_sk, &to_sign, b"QRYPTO-SERVER-RESPONSE", seed)
            .map_err(|_| anyhow::anyhow!("Failed signature"))?;

        let signed_payload = SignedPayload {
            data: data_bytes,
            signature: signature.as_slice().to_vec(),
            timestamp,
        };
        let signed_bytes = serde_json::to_vec(&signed_payload)?;

        // Encrypt
        let hk = Hkdf::<Sha3_256>::new(None, &shared_secret);
        let mut sym_key = [0u8; 32];
        hk.expand(b"qrypto-session-key", &mut sym_key)
            .map_err(|e| anyhow::anyhow!("Failed to generate sym key: {}", e))?;

        let cipher = XChaCha20Poly1305::new(&sym_key.into());
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let payload_ct = cipher
            .encrypt(nonce, signed_bytes.as_ref())
            .map_err(|e| anyhow!("Enc failed: {}", e))?;

        Ok(EncryptedResponse {
            payload_ct,
            nonce: nonce_bytes,
        })
    }
}
