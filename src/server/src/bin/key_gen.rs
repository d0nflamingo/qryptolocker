use libcrux_ml_dsa::ml_dsa_87;
use libcrux_ml_kem::mlkem1024;
use rand::{RngCore, rngs::OsRng};
use std::fs::{self, File};
use std::io::Write;

fn main() -> anyhow::Result<()> {
    println!("🔑 Generating Crypto Keys...");

    let data_dir = "../../data";
    fs::create_dir_all(data_dir)?;

    // 1. Generate Server ML-KEM-1024 Pair (For Encryption)
    let mut rng = OsRng;
    let mut seed = [0u8; 64];
    rng.fill_bytes(&mut seed);
    let kem_kp = mlkem1024::generate_key_pair(seed);

    // Use .as_ref() to access the underlying byte array of the keys
    File::create(format!("{}/server_kem.pub", data_dir))?
        .write_all(kem_kp.public_key().as_ref())?;
    File::create(format!("{}/server_kem.priv", data_dir))?
        .write_all(kem_kp.private_key().as_ref())?;
    println!("✅ Generated Server KEM Keys");

    // 2. Generate Server ML-DSA-87 Pair (For Signing Responses)
    let mut seed = [0u8; 32];
    rng.try_fill_bytes(&mut seed).unwrap();
    let dsa_kp = ml_dsa_87::generate_key_pair(seed);

    // DSA keys also implement AsRef<[u8]>
    File::create(format!("{}/server_dsa.pub", data_dir))?
        .write_all(dsa_kp.verification_key.as_ref())?;
    File::create(format!("{}/server_dsa.priv", data_dir))?
        .write_all(dsa_kp.signing_key.as_ref())?;
    println!("✅ Generated Server DSA Keys");

    Ok(())
}
