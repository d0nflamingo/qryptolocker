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
use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

// Bundled Server Keys
const SERVER_KEM_PK: &[u8] = include_bytes!("../../../data/server_kem.pub");
const SERVER_DSA_VK: &[u8] = include_bytes!("../../../data/server_dsa.pub");

pub struct SecureClient {
    client_dsa_sk: ml_dsa_87::MLDSA87SigningKey,
    client_dsa_vk: ml_dsa_87::MLDSA87VerificationKey,
    server_kem_pk: mlkem1024::MlKem1024PublicKey,
    server_dsa_vk: ml_dsa_87::MLDSA87VerificationKey,
}

impl SecureClient {
    pub fn new() -> Result<Self> {
        // Generate ephemeral signing keys for this session/client
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let key_pair = ml_dsa_87::generate_key_pair(seed);
        seed.zeroize();

        // Load static server keys
        let server_kem_bytes: [u8; 1568] = SERVER_KEM_PK
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid Server KEM key size"))?;
        let server_kem = mlkem1024::MlKem1024PublicKey::from(server_kem_bytes);

        let server_dsa_bytes: [u8; 2592] = SERVER_DSA_VK
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid Server DSA key size"))?;
        let server_dsa = ml_dsa_87::MLDSA87VerificationKey::new(server_dsa_bytes);

        Ok(Self {
            client_dsa_sk: key_pair.signing_key,
            client_dsa_vk: key_pair.verification_key,
            server_kem_pk: server_kem,
            server_dsa_vk: server_dsa,
        })
    }

    /// Encrypts, Signs and Encapsulates a request
    pub fn encrypt_request<T: Serialize>(&self, data: &T) -> Result<(EncryptedRequest, [u8; 32])> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let (kem_ct, shared_secret) = mlkem1024::encapsulate(&self.server_kem_pk, seed);
        seed.zeroize();

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("Time error: {}", e))?
            .as_secs();

        // Sign the request
        let data_bytes = serde_json::to_vec(data)?;
        let mut to_sign = data_bytes.clone();
        to_sign.extend_from_slice(&timestamp.to_le_bytes());

        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signature = ml_dsa_87::sign(
            &self.client_dsa_sk,
            &to_sign,
            b"QRYPTO-CLIENT-REQUEST",
            seed,
        )
        .map_err(|_| anyhow::anyhow!("Failed signature"))?;
        seed.zeroize();

        let signed_payload = SignedPayload {
            data: data_bytes,
            signature: signature.as_slice().to_vec(),
            timestamp,
        };
        let signed_bytes = serde_json::to_vec(&signed_payload)?;

        // Derive Symmetric Key (Sha3 of Shared Secret)
        let hk = Hkdf::<Sha3_256>::new(None, &shared_secret);
        let mut sym_key = [0u8; 32];
        hk.expand(b"qrypto-session-key", &mut sym_key)
            .map_err(|e| anyhow::anyhow!("Failed to generate symmetric key: {}", e))?;

        // Encrypt request
        let cipher = XChaCha20Poly1305::new(&sym_key.into());
        sym_key.zeroize();

        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let payload_ct = cipher
            .encrypt(nonce, signed_bytes.as_ref())
            .map_err(|e| anyhow!("Encryption error: {}", e))?;

        Ok((
            EncryptedRequest {
                kem_ct: kem_ct.as_ref().to_vec(),
                payload_ct,
                client_vk: self.client_dsa_vk.as_ref().to_vec(),
                nonce: nonce_bytes,
            },
            shared_secret,
        ))
    }

    /// Decrypts and Verifies a response using the established shared secret
    pub fn decrypt_response<T: for<'a> Deserialize<'a>>(
        &self,
        response: EncryptedResponse,
        mut shared_secret: [u8; 32],
    ) -> Result<T> {
        // Derive shared secret into key
        let hk = Hkdf::<Sha3_256>::new(None, &shared_secret);
        shared_secret.zeroize();

        let mut sym_key = [0u8; 32];
        hk.expand(b"qrypto-session-key", &mut sym_key)
            .map_err(|e| anyhow::anyhow!("Failed to generate sym key: {}", e))?;

        // Decrypt response
        let cipher = XChaCha20Poly1305::new(&sym_key.into());
        sym_key.zeroize();

        let nonce = XNonce::from_slice(&response.nonce);
        let plaintext = cipher
            .decrypt(nonce, response.payload_ct.as_ref())
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        // Verify Signature
        let signed_payload: SignedPayload = serde_json::from_slice(&plaintext)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("Time error: {}", e))?
            .as_secs();

        let drift = now.abs_diff(signed_payload.timestamp);
        if drift > 300 {
            return Err(anyhow::anyhow!("Response timestamp expired"));
        }

        let mut sig_arr = [0u8; 4627];
        if signed_payload.signature.len() != 4627 {
            return Err(anyhow!("Invalid signature length"));
        }

        sig_arr.copy_from_slice(&signed_payload.signature);
        let sig = ml_dsa_87::MLDSA87Signature::new(sig_arr);

        let mut to_verify = signed_payload.data.clone();
        to_verify.extend_from_slice(&signed_payload.timestamp.to_le_bytes());

        ml_dsa_87::verify(
            &self.server_dsa_vk,
            &to_verify,
            b"QRYPTO-SERVER-RESPONSE",
            &sig,
        )
        .map_err(|_| anyhow!("Invalid Server Signature"))?;

        let data: T = serde_json::from_slice(&signed_payload.data)?;

        Ok(data)
    }
}
