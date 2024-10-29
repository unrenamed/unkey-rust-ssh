use std::collections::HashMap;
use std::env;
use std::sync::Arc;

use async_trait::async_trait;
use log::info;
use russh::keys::*;
use russh::server::{Msg, Server as _, Session};
use russh::*;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use unkey::models::VerifyKeyRequest;
use unkey::Client as UnkeyClient;

// Lazy initialization of environment variables using the `lazy_static` macro
lazy_static::lazy_static! {
    static ref UNKEY_ROOT_KEY: String = get_env("UNKEY_ROOT_KEY", "");
    static ref UNKEY_API_ID: String = get_env("UNKEY_API_ID", "");
}

/// Helper function to retrieve environment variables with a default fallback value
fn get_env(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Data structure for holding the result of API key verification
#[derive(Serialize, Deserialize, Debug)]
struct KeyVerifyData {
    valid: bool,
}

#[tokio::main]
async fn main() {
    // Load environment variables from `.env` file if available
    dotenv::dotenv().ok();

    // Initialize logger for debug information
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    // Configure SSH server settings, such as timeouts and authentication handling
    let config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![russh_keys::key::KeyPair::generate_ed25519().unwrap()],
        ..Default::default()
    };
    let config = Arc::new(config);

    // Initialize and run the server on a specified address and port
    let mut server_instance = Server {
        clients: Arc::new(Mutex::new(HashMap::new())),
        id: 0,
        connect_username: String::new(),
    };
    server_instance
        .run_on_address(config, ("0.0.0.0", 2222))
        .await
        .unwrap();
}

/// Struct representing the SSH server, storing connected clients and unique identifiers
#[derive(Clone)]
struct Server {
    clients: Arc<Mutex<HashMap<(usize, ChannelId), russh::server::Handle>>>,
    id: usize,
    connect_username: String,
}

impl Server {
    /// Broadcasts data to all connected clients except the sender (if `exclude_self` is true)
    async fn post(&mut self, data: CryptoVec, exclude_self: bool) {
        let mut clients = self.clients.lock().await;
        for ((client_id, channel), client_handle) in clients.iter_mut() {
            if !exclude_self || *client_id != self.id {
                let _ = client_handle.data(*channel, data.clone()).await;
            }
        }
    }
}

/// Implementation of the SSH `Server` trait to handle new clients and session errors
impl server::Server for Server {
    type Handler = Self;

    /// Creates a new client connection and assigns a unique ID
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        self.id += 1;
        self.clone()
    }

    /// Logs any session errors that occur
    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        eprintln!("Session error: {:#?}", error);
    }
}

#[async_trait]
impl server::Handler for Server {
    type Error = russh::Error;

    /// Opens a new session channel for the client and adds them to the list of connected clients
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        {
            let mut clients = self.clients.lock().await;
            clients.insert((self.id, channel.id()), session.handle());
        }

        let message = format!("{} connected to the server.\r\n", self.connect_username);
        self.post(CryptoVec::from(message), false).await;
        Ok(true)
    }

    /// Authenticates a client using a password by verifying the key with the Unkey service
    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        info!("Received credentials: {}, {}", user, password);

        match verify_key(password).await {
            Some(key) if !key.valid => Ok(server::Auth::Reject {
                proceed_with_methods: Some(MethodSet::PASSWORD),
            }),
            _ => {
                self.connect_username = user.to_string();
                Ok(server::Auth::Accept)
            }
        }
    }

    /// Rejects authentication by public key, prompting clients to use passwords
    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Reject {
            proceed_with_methods: Some(MethodSet::PASSWORD),
        })
    }

    /// Handles data received from the client, sending it to all other clients
    async fn data(
        &mut self,
        _: ChannelId,
        data: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        // Sending Ctrl+C ends the session and disconnects the client
        if data == [3] {
            let message = format!(
                "{} disconnected from the server.\r\n",
                self.connect_username
            );
            self.post(CryptoVec::from(message), true).await;
            return Err(russh::Error::Disconnect);
        }

        // Broadcast client message to all other clients
        let message = format!(
            "[{}]: {}\r\n",
            self.connect_username,
            String::from_utf8_lossy(data)
        );
        self.post(CryptoVec::from(message), false).await;
        Ok(())
    }

    /// Sets up port forwarding to allow clients to access services through this server
    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let handle = session.handle();
        let address = address.to_string();
        let port = *port;

        // Spawns a background task for port forwarding
        tokio::spawn(async move {
            let channel = handle
                .channel_open_forwarded_tcpip(address, port, "1.2.3.4", 1234)
                .await
                .unwrap();
            let _ = channel.data(&b"Hello from a forwarded port"[..]).await;
            let _ = channel.eof().await;
        });

        Ok(true)
    }
}

/// Function to verify an API key using the Unkey service, returning `KeyVerifyData`
async fn verify_key(key: &str) -> Option<KeyVerifyData> {
    let unkey_client = UnkeyClient::new(UNKEY_ROOT_KEY.as_str());
    let req = VerifyKeyRequest::new(key, UNKEY_API_ID.as_str());

    unkey_client
        .verify_key(req)
        .await
        .ok()
        .map(|res| KeyVerifyData { valid: res.valid })
}
