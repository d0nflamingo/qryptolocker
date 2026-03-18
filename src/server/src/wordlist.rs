use anyhow::Result;
use flate2::read::GzDecoder;
use hkdf::Hkdf;
use once_cell::sync::Lazy;
use sha3::Sha3_256;
use std::io::Read;

const WORDLIST_COMPRESSED: &[u8] = include_bytes!("../../../data/words_compressed.tar.gz");

static DICTIONARY: Lazy<Vec<String>> = Lazy::new(|| {
    let mut decoder = GzDecoder::new(WORDLIST_COMPRESSED);
    let mut decompressed = String::new();
    decoder
        .read_to_string(&mut decompressed)
        .expect("Failed to decompress wordlist");
    decompressed.lines().map(String::from).collect()
});

pub fn generate_word_for_path(file_path: &str, master_salt: &[u8; 16]) -> Result<String> {
    let dict = &*DICTIONARY;

    let hk = Hkdf::<Sha3_256>::new(Some(b"qrypto-word-derivation"), master_salt);
    let mut index_bytes = [0u8; 8];
    hk.expand(file_path.as_bytes(), &mut index_bytes)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    let hash_value = u64::from_le_bytes(index_bytes);

    let index = (hash_value % dict.len() as u64) as usize;

    Ok(dict[index].clone())
}
