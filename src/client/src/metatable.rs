use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub path: PathBuf,
    pub enc_word: Vec<u8>,
    pub word_enc_nonce: [u8; 24],
    pub file_nonce: [u8; 24],
    pub file_salt: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirMetadata {
    pub path: PathBuf,
    pub enc_word: Vec<u8>,
    pub word_enc_nonce: [u8; 24],
    pub dir_key_salt: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaTableContent {
    pub files: Vec<FileMetadata>,
    pub subdirs: Vec<DirMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaTable {
    pub content: MetaTableContent,
    pub mac: [u8; 32],
}
