use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientData {
    pub client_id: Uuid,
    pub root_word: String,
    pub key_wrapper_salt: [u8; 16],
    pub salt_word_global: [u8; 16],
    pub payment_received: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientStorage {
    clients: HashMap<Uuid, ClientData>,
}

impl Default for ClientStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientStorage {
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }

    pub fn add_client(&mut self, data: ClientData) {
        self.clients.insert(data.client_id, data);
    }

    pub fn get_client(&self, id: &Uuid) -> Option<&ClientData> {
        self.clients.get(id)
    }

    pub fn get_client_mut(&mut self, id: &Uuid) -> Option<&mut ClientData> {
        self.clients.get_mut(id)
    }

    pub fn list_clients(&self) -> Vec<&ClientData> {
        let clients: Vec<&ClientData> = self.clients.values().collect();
        clients
    }

    pub fn save_to_disk(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.clients)?;
        std::fs::write("clients_db.json", json)?;
        Ok(())
    }

    pub fn load_from_disk() -> Result<Self> {
        let json = std::fs::read_to_string("clients_db.json")?;
        let clients = serde_json::from_str(&json)?;
        Ok(Self { clients })
    }
}
