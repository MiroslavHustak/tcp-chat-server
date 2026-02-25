Here is one single, self-contained Markdown file with the entire educational explanation and all code blocks in a logical, flowing structure.
You can copy-paste this whole content into a file called e.g. tcp-chat-server-relay-only.md.markdown

# TCP Chat Server – Relay-Only Version (Educational)

A complete Rust TCP chat server that enforces **true end-to-end encryption**:

- The server **never decrypts or encrypts user chat messages**
- It only relays encrypted blobs exactly as received from clients
- It decrypts **only the username** (for prefixing and bookkeeping)
- System messages ("Alice joined", "Bob left") are encrypted by the server
- Thread-per-client architecture
- Dedicated writer thread per client using cloned `TcpStream`
- `mpsc` channel per client as a mailbox / actor-style queue
- Shared client list via `Arc<Mutex<HashMap<…>>>`
- Functional/iterator style loops wherever reasonable

**Educational focus:** Encrypted payloads are printed in hex on the console so you can see what travels over the wire.

## Features Demonstrated

- End-to-end encryption with libsodium `secretbox` (ChaCha20-Poly1305)
- Length-prefixed protocol (4-byte big-endian length + payload)
- Safe concurrent read/write on single TCP connection via stream cloning
- Clean disconnection & cleanup (join/leave notifications)
- Username collision prevention
- Maximum message size protection

## Dependencies

```rust
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::hash::sha256;

Constantsrust

/// Maximum allowed message size (1 MB) – prevents memory exhaustion attacks
const MAX_MESSAGE_SIZE: usize = 1_000_000;

Pure Utility Functionsrust

/// Bytes → space-separated lowercase hex (debug / educational display only)
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

/// Derive 32-byte secretbox key from passphrase via SHA-256  
/// (educational only – **not production-secure**; prefer Argon2id + per-user salt)
fn derive_key_from_passphrase(passphrase: &str) -> secretbox::Key {
    let hash = sha256::hash(passphrase.as_bytes());
    secretbox::Key::from_slice(&hash.0).expect("SHA-256 is always 32 bytes")
}

/// Concatenate already-encrypted prefix + already-encrypted message
fn prepend_encrypted_username(prefix: &[u8], msg: &[u8]) -> Vec<u8> {
    prefix.iter().copied().chain(msg.iter().copied()).collect()
}

I/O Helpers (Length-Prefixed Protocol)rust

fn read_message_length<R: Read>(reader: &mut R) -> io::Result<usize> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    Ok(u32::from_be_bytes(len_buf) as usize)
}

fn read_encrypted_bytes<R: Read>(reader: &mut R, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn receive_encrypted_message<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let len = read_message_length(reader)?;
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Message too large"));
    }
    read_encrypted_bytes(reader, len)
}

fn send_encrypted_message<W: Write>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(data)?;
    writer.flush()
}

Display Helpers (Educational Only)rust

/// Show first ~60 bytes of encrypted payload in hex
fn display_encrypted_hex(username: &str, encrypted: &[u8], prefix: &str) {
    let preview_len = encrypted.len().min(60);
    let hex = bytes_to_hex(&encrypted[..preview_len]);
    let suffix = if encrypted.len() > preview_len {
        format!(" … ({} bytes total)", encrypted.len())
    } else {
        String::new()
    };
    println!("{} {}: [ENCRYPTED] {} {}", prefix, username, hex, suffix);
}

Username & System Message Handlingrust

/// Decrypt username only (used once during registration)
fn extract_username_identifier(encrypted: &[u8], key: &secretbox::Key) -> Option<String> {
    if encrypted.len() < secretbox::NONCEBYTES { return None; }
    let nonce = secretbox::Nonce::from_slice(&encrypted[..secretbox::NONCEBYTES])?;
    let ciphertext = &encrypted[secretbox::NONCEBYTES..];

    let plaintext = secretbox::open(ciphertext, &nonce, key).ok()?;
    let username = String::from_utf8(plaintext).ok()?;

    if username.trim().is_empty() { None } else { Some(username.trim().to_string()) }
}

/// Encrypt "username: " once → reused for every message this user sends
fn create_encrypted_username_prefix(username: &str, key: &secretbox::Key) -> Vec<u8> {
    let prefix = format!("{}: ", username);
    let nonce = secretbox::gen_nonce();
    let ciphertext = secretbox::seal(prefix.as_bytes(), &nonce, key);
    nonce.0.to_vec().into_iter().chain(ciphertext).collect()
}

/// Encrypt server-generated system message
fn create_encrypted_system_message(text: String, key: &secretbox::Key) -> Vec<u8> {
    let nonce = secretbox::gen_nonce();
    let ciphertext = secretbox::seal(text.as_bytes(), &nonce, key);
    nonce.0.to_vec().into_iter().chain(ciphertext).collect()
}

Typesrust

type ClientSender = Sender<Vec<u8>>;

struct ClientInfo {
    sender: ClientSender,
    encrypted_username_prefix: Vec<u8>,
}

type ClientMap = Arc<Mutex<HashMap<String, ClientInfo>>>;

Core Business Logicrust

fn register_client(clients: &ClientMap, username: String, info: ClientInfo) -> Result<(), String> {
    let mut map = clients.lock().unwrap();
    if map.contains_key(&username) {
        Err(format!("Username {} already taken", username))
    } else {
        map.insert(username, info);
        Ok(())
    }
}

fn broadcast_to_others(clients: &ClientMap, sender_name: &str, encrypted_msg: &[u8]) {
    let map = clients.lock().unwrap();
    let prefix = match map.get(sender_name) {
        Some(info) => &info.encrypted_username_prefix,
        None => return,
    };
    let full_message = prepend_encrypted_username(prefix, encrypted_msg);

    map.iter()
        .filter(|(name, _)| *name != sender_name)
        .for_each(|(_, info)| { let _ = info.sender.send(full_message.clone()); });
}

fn broadcast_to_all(clients: &ClientMap, message: Vec<u8>) {
    clients.lock().unwrap()
        .values()
        .for_each(|info| { let _ = info.sender.send(message.clone()); });
}

Writer Thread Pattern – Concurrent Read/Write on One Connectionrust

/// Dedicated thread that drains the per-client channel and writes to TCP
fn spawn_sender_thread(mut writer: TcpStream, rx: mpsc::Receiver<Vec<u8>>) {
    thread::spawn(move || {
        rx.into_iter()
            .try_for_each(|msg| send_encrypted_message(&mut writer, &msg))
            .ok(); // ignore errors → thread exits on disconnect
    });
}

Why clone the stream?A single TcpStream cannot be safely used for reading and writing from two threads simultaneously.
Cloning gives two independent handles to the same underlying socket — reads and writes proceed concurrently without blocking each other.Client Connection Handlerrust

fn handle_client(mut stream: TcpStream, clients: ClientMap, key: secretbox::Key) {
    // Receive & validate username (only decryption of user-controlled data)
    let username = receive_encrypted_message(&mut stream)
        .ok()
        .and_then(|data| extract_username_identifier(&data, &key))
        .filter(|name| !name.is_empty());

    let username = match username {
        Some(name) => name,
        None => {
            eprintln!("Failed to receive valid username");
            return;
        }
    };

    println!("\n>>> {} joined", username);

    // Setup per-client channel + pre-encrypted prefix
    let (tx, rx) = mpsc::channel();
    let encrypted_username_prefix = create_encrypted_username_prefix(&username, &key);

    let client_info = ClientInfo {
        sender: tx,
        encrypted_username_prefix,
    };

    // Register or reject (username taken)
    if let Err(e) = register_client(&clients, username.clone(), client_info) {
        eprintln!("{}", e);
        return;
    }

    // Announce join
    let join_msg = create_encrypted_system_message(format!("{} joined", username), &key);
    broadcast_to_others(&clients, &username, &join_msg);

    // Spawn writer thread (owns cloned stream)
    let writer = stream.try_clone().expect("clone failed");
    spawn_sender_thread(writer, rx);

    // Main receive loop – functional style
    std::iter::from_fn(|| receive_encrypted_message(&mut stream).ok())
        .filter(|msg| !msg.is_empty())
        .try_for_each(|encrypted_msg| {
            display_encrypted_hex(&username, &encrypted_msg, ">>>");
            broadcast_to_others(&clients, &username, &encrypted_msg);
            Ok::<(), ()>(())
        })
        .ok();

    // Cleanup
    clients.lock().unwrap().remove(&username);
    println!("\n<<< {} disconnected");

    let leave_msg = create_encrypted_system_message(format!("{} left", username), &key);
    broadcast_to_all(&clients, leave_msg);
}

Main Entry Pointrust

fn main() -> io::Result<()> {
    sodiumoxide::init().expect("libsodium init failed");

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║          Relay-Only Encrypted Chat Server                  ║");
    println!("╠════════════════════════════════════════════════════════════╣");
    println!("║  Port:              5555                                   ║");
    println!("║  Cipher:            ChaCha20-Poly1305 (secretbox)          ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    println!("⚠️  All clients **must use the same passphrase**!\n");
    print!("Enter encryption passphrase: ");
    io::stdout().flush()?;

    let mut passphrase = String::new();
    io::stdin().read_line(&mut passphrase)?;
    let passphrase = passphrase.trim();

    if passphrase.is_empty() {
        eprintln!("Error: Passphrase cannot be empty!");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Empty passphrase"));
    }

    let key = derive_key_from_passphrase(passphrase);
    println!("✅ Key derived\n");

    let clients: ClientMap = Arc::new(Mutex::new(HashMap::new()));
    let listener = TcpListener::bind("0.0.0.0:5555")?;

    println!("Server listening on port 5555 – waiting for connections...\n");

    listener.incoming()
        .filter_map(Result::ok)
        .for_each(|stream| {
            let clients = Arc::clone(&clients);
            let key = key.clone();
            thread::spawn(move || handle_client(stream, clients, key));
        });

    Ok(())
}

```

