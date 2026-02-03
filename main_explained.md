/*
// ============================================================
// TCP Chat Server - Relay-Only Version
// ============================================================
// This server demonstrates:
// - End-to-end encryption (server ONLY relays encrypted messages)
// - Thread-per-client architecture
// - Message-passing between threads (mpsc channels)
// - Shared state with Arc<Mutex<T>>
// - Iterator-based control flow
//
// IMPORTANT: Server NEVER encrypts or decrypts messages!
// Messages are relayed exactly as received (encrypted).
// For learning: displays encrypted hex on console.
// ============================================================

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::hash::sha256;

// ============================================================
// Constants
// ============================================================

/// Maximum message size (1 MB) to prevent memory exhaustion attacks
const MAX_MESSAGE_SIZE: usize = 1_000_000;

// ============================================================
// Pure utility functions (no I/O, no side effects)
// ============================================================

/// Convert bytes to hexadecimal string for display
///
/// Example: [72, 101, 108, 108, 111] -> "48 65 6c 6c 6f"
/// Used for displaying encrypted messages in readable format
///
/// For learning purposes: Shows what encrypted data looks like on the wire
fn bytes_to_hex(bytes: &[u8]) -> String {
bytes.iter()
.map(|b| format!("{:02x}", b))  // Format each byte as 2-digit hex
.collect::<Vec<_>>()
.join(" ")  // Join with spaces
}

/// Derive 32-byte encryption key from user passphrase
///
/// Uses SHA-256 hash to convert any length passphrase into 32-byte key.
/// This is SIMPLE but NOT IDEAL for production (should use Argon2/PBKDF2).
///
/// # Arguments
/// * `passphrase` - User-entered passphrase
///
/// # Returns
/// 32-byte key suitable for secretbox
///
/// # Security Note
/// SHA-256 is fast, making it vulnerable to brute-force attacks.
/// Production should use slow KDF like Argon2 with salt.
fn derive_key_from_passphrase(passphrase: &str) -> secretbox::Key {
// Hash the passphrase to get 32 bytes
let hash = sha256::hash(passphrase.as_bytes());

    // Convert hash to key
    secretbox::Key::from_slice(&hash.0)
        .expect("SHA-256 always produces 32 bytes")
}

/// Prepend encrypted username to encrypted message
///
/// Takes encrypted username prefix and chains it with encrypted message.
/// Server works purely with encrypted data - no decryption for relay!
///
/// # Arguments
/// * `encrypted_username_prefix` - Already-encrypted "username: " bytes
/// * `encrypted_msg` - Already-encrypted message bytes
///
/// # Returns
/// Combined encrypted bytes: encrypted("username: ") + encrypted(message)
fn prepend_encrypted_username(encrypted_username_prefix: &[u8], encrypted_msg: &[u8]) -> Vec<u8> {
encrypted_username_prefix
.iter()
.copied()
.chain(encrypted_msg.iter().copied())  // Chain encrypted bytes
.collect()
}

// ============================================================
// I/O functions (ordered by dependency)
// ============================================================

/// Read message length from stream (first 4 bytes)
///
/// Protocol: Each message is prefixed with its length as 4-byte big-endian u32
/// This tells us exactly how many bytes to read for the message body.
///
/// # Errors
/// Returns error if stream is closed or read fails
fn read_message_length<R: Read>(reader: &mut R) -> io::Result<usize> {
let mut len_buf = [0u8; 4];        // Buffer for 4-byte length
reader.read_exact(&mut len_buf)?;  // Read exactly 4 bytes (or error)
Ok(u32::from_be_bytes(len_buf) as usize)  // Convert big-endian to usize
}

/// Read encrypted message bytes from stream
///
/// Reads exactly `len` bytes - no more, no less.
/// Used after reading the message length.
///
/// Server does NOT decrypt - just reads encrypted bytes as-is
fn read_encrypted_bytes<R: Read>(reader: &mut R, len: usize) -> io::Result<Vec<u8>> {
let mut encrypted = vec![0u8; len];  // Allocate buffer of exact size
reader.read_exact(&mut encrypted)?;   // Read exactly len bytes (or error)
Ok(encrypted)
}

/// Receive encrypted message from stream
///
/// HIGH-LEVEL FUNCTION that combines:
/// 1. Read message length
/// 2. Validate size (prevent memory attacks)
/// 3. Read encrypted bytes
///
/// Note: Server does NOT decrypt! Returns encrypted bytes unchanged.
fn receive_encrypted_message<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
let len = read_message_length(reader)?;

    // Pattern matching for validation
    match len <= MAX_MESSAGE_SIZE {
        false => Err(io::Error::new(io::ErrorKind::InvalidData, "Message too large")),
        true => read_encrypted_bytes(reader, len)
    }
}

/// Send encrypted message to stream
///
/// Protocol:
/// 1. Send length as 4-byte big-endian u32
/// 2. Send encrypted bytes (as-is, no modification)
/// 3. Flush to ensure immediate sending
///
/// Uses functional chaining with `and_then`
fn send_encrypted_message<W: Write>(writer: &mut W, encrypted: &[u8]) -> io::Result<()> {
let len = encrypted.len() as u32;
writer.write_all(&len.to_be_bytes())           // Write length
.and_then(|_| writer.write_all(encrypted)) // Then write encrypted data
.and_then(|_| writer.flush())              // Then flush
}

// ============================================================
// Display functions (for learning purposes only)
// ============================================================

/// Display encrypted message in hexadecimal format
///
/// EDUCATIONAL ONLY: Shows what encrypted data looks like.
/// Server never decrypts - only displays hex representation.
///
/// # Arguments
/// * `username` - Username identifier (from registration, stored as plaintext)
/// * `encrypted` - Encrypted message bytes
/// * `prefix` - Display prefix (e.g., ">>>")
fn display_encrypted_hex(username: &str, encrypted: &[u8], prefix: &str) {
// Show first 60 bytes of hex (or less if message is shorter)
let preview_len = encrypted.len().min(60);
let hex = bytes_to_hex(&encrypted[..preview_len]);

    let suffix = match encrypted.len() > preview_len {
        true => format!("... ({} bytes total)", encrypted.len()),
        false => String::new(),
    };

    println!("{} {}: [ENCRYPTED] {} {}",
             prefix, username, hex, suffix);
}

// ============================================================
// Encryption functions (only for username and system messages)
// ============================================================

/// Extract username identifier from encrypted data
///
/// For server management, we need a username identifier.
/// Client sends encrypted username first - we decrypt ONLY for bookkeeping.
/// User messages are NEVER decrypted by server!
///
/// Uses Option type (like F#) for explicit handling of invalid cases.
fn extract_username_identifier(encrypted: &[u8], key: &secretbox::Key) -> Option<String> {
// Decrypt ONLY for server-side identifier (not for relaying)
match encrypted.len() < secretbox::NONCEBYTES {
true => None,
false => {
let nonce = secretbox::Nonce::from_slice(&encrypted[..secretbox::NONCEBYTES])?;
let ciphertext = &encrypted[secretbox::NONCEBYTES..];

            let plaintext = secretbox::open(ciphertext, &nonce, key).ok()?;
            let username = String::from_utf8(plaintext).ok()?;

            match username.trim().is_empty() {
                true => None,
                false => Some(username.trim().to_string()),
            }
        }
    }
}

/// Create encrypted username prefix for relaying
///
/// Encrypts "username: " so it can be prepended to relayed messages.
/// This is done once per client and reused for all their messages.
///
/// # Arguments
/// * `username` - Plain username identifier
/// * `key` - Encryption key
///
/// # Returns
/// Encrypted bytes of "username: " format
fn create_encrypted_username_prefix(username: &str, key: &secretbox::Key) -> Vec<u8> {
let prefix = format!("{}: ", username);
let nonce = secretbox::gen_nonce();
let ciphertext = secretbox::seal(prefix.as_bytes(), &nonce, key);

    let mut result = nonce.0.to_vec();
    result.extend_from_slice(&ciphertext);
    result
}

/// Create encrypted system message (join/leave notifications)
///
/// System messages like "Alice joined" are created by server,
/// so they need to be encrypted before sending to clients.
fn create_encrypted_system_message(text: String, key: &secretbox::Key) -> Vec<u8> {
let nonce = secretbox::gen_nonce();
let ciphertext = secretbox::seal(text.as_bytes(), &nonce, key);

    let mut result = nonce.0.to_vec();
    result.extend_from_slice(&ciphertext);
    result
}

// ============================================================
// Type aliases (for clarity and maintainability)
// ============================================================

/// Sender for client's message channel
/// Each client has a channel for receiving broadcast messages
type ClientSender = Sender<Vec<u8>>;

/// Client information stored in server
/// Contains both the channel sender and encrypted username prefix
struct ClientInfo {
sender: ClientSender,
encrypted_username_prefix: Vec<u8>,  // Pre-encrypted "username: " for relaying
}

/// Shared map of connected clients
/// Arc = Atomic Reference Counting (thread-safe shared ownership)
/// Mutex = Mutual exclusion lock (only one thread can access at a time)
/// HashMap = username -> ClientInfo
type ClientMap = Arc<Mutex<HashMap<String, ClientInfo>>>;

// ============================================================
// Business logic functions
// ============================================================

/// Register a new client in the shared client map
///
/// Thread-safe: Uses Mutex to ensure only one thread modifies map at a time.
///
/// # Arguments
/// * `clients` - Shared client map
/// * `username` - Username identifier to register
/// * `info` - Client info (sender + encrypted username prefix)
///
/// # Returns
/// Ok(()) if successful, Err(message) if username already taken
fn register_client(clients: &ClientMap, username: String, info: ClientInfo) -> Result<(), String> {
let mut map = clients.lock().unwrap();  // Acquire lock (blocks if another thread has it)
match map.contains_key(&username) {
true => Err(format!("Username {} already taken", username)),
false => {
map.insert(username, info);
Ok(())
}
}
// Lock automatically released when `map` goes out of scope
}

/// Broadcast encrypted message to all clients except sender
///
/// Filters out sender, prepends encrypted username, sends to everyone else.
///
/// # Arguments
/// * `clients` - Shared client map
/// * `sender_name` - Username identifier of sender (to exclude)
/// * `encrypted_msg` - Encrypted message to broadcast
fn broadcast_to_others(clients: &ClientMap, sender_name: &str, encrypted_msg: &[u8]) {
let map = clients.lock().unwrap();

    // Get sender's encrypted username prefix
    let encrypted_username_prefix = match map.get(sender_name) {
        Some(info) => &info.encrypted_username_prefix,
        None => return,  // Sender not found, skip broadcast
    };

    // Prepend encrypted username to encrypted message
    let full_message = prepend_encrypted_username(encrypted_username_prefix, encrypted_msg);

    // Broadcast to all except sender
    map.iter()
        .filter(|(name, _)| *name != sender_name)  // Exclude sender
        .for_each(|(_, info)| {
            info.sender.send(full_message.clone()).ok();  // Send encrypted message
        });
}

/// Broadcast encrypted message to ALL connected clients
///
/// Used for system messages (join/leave notifications).
///
/// # Arguments
/// * `clients` - Shared client map
/// * `message` - Encrypted message to broadcast
fn broadcast_to_all(clients: &ClientMap, message: Vec<u8>) {
clients.lock().unwrap()
.values()  // Only need client info, not usernames
.for_each(|info| {
info.sender.send(message.clone()).ok();
});
}

// ============================================================
// Thread management
// ============================================================

/// Spawn a thread to send encrypted messages to a client
///
/// Each client has TWO threads:
/// 1. Main thread (handle_client): receives encrypted messages from client
/// 2. Sender thread (this): sends encrypted messages to client
///
/// This separation prevents blocking: receiving can happen
/// while sending is in progress, and vice versa.
///
/// # Arguments
/// * `writer` - TCP stream for writing
/// * `rx` - Channel receiver for encrypted messages to send
fn spawn_sender_thread(mut writer: TcpStream, rx: mpsc::Receiver<Vec<u8>>) {
thread::spawn(move || {
rx.into_iter()  // Convert receiver to iterator
// Send each encrypted message until error or channel closes
.try_for_each(|encrypted_msg| send_encrypted_message(&mut writer, &encrypted_msg))
.ok();  // Ignore result (client disconnected)
});
}

// ============================================================
// Client handler (uses all above functions)
// ============================================================

/// Handle a single client connection
///
/// This function:
/// 1. Receives and validates encrypted username
/// 2. Registers client in shared map
/// 3. Spawns sender thread for this client
/// 4. Receives encrypted messages from client in loop
/// 5. Broadcasts encrypted messages to other clients
/// 6. Cleans up on disconnect
///
/// IMPORTANT: Server NEVER decrypts user messages for relaying!
/// Only username is decrypted for server bookkeeping.
///
/// # Arguments
/// * `stream` - TCP connection to this client
/// * `clients` - Shared map of all connected clients
/// * `key` - Encryption key (only used for username extraction and system messages)
fn handle_client(mut stream: TcpStream, clients: ClientMap, key: secretbox::Key) {
// ========== Username Setup ==========

    // Receive encrypted username and extract identifier using functional composition
    let username = receive_encrypted_message(&mut stream)
        .ok()                                                    // Convert Result to Option
        .and_then(|data| extract_username_identifier(&data, &key)) // Extract username identifier
        .filter(|name| !name.is_empty());                        // Filter out empty names

    let username = match username {
        Some(name) => name,
        None => {
            eprintln!("Failed to receive valid username");
            return;  // Exit handler, connection will close
        }
    };

    println!("\n>>> {} joined", username);

    // ========== Client Registration ==========

    // Create channel for sending encrypted messages to this client
    let (tx, rx) = mpsc::channel::<Vec<u8>>();

    // Create encrypted username prefix for relaying (done once, reused for all messages)
    let encrypted_username_prefix = create_encrypted_username_prefix(&username, &key);

    let client_info = ClientInfo {
        sender: tx,
        encrypted_username_prefix,
    };

    // Register client (pattern matching for error handling)
    match register_client(&clients, username.clone(), client_info) {
        Err(e) => {
            eprintln!("{}", e);
            return;  // Username taken, close connection
        }
        Ok(_) => ()  // Success, continue
    }

    // ========== Broadcast Join Message ==========

    // Notify other clients that this user joined (encrypted system message)
    let join_msg = create_encrypted_system_message(format!("{} joined", username), &key);
    broadcast_to_others(&clients, &username, &join_msg);

    // ========== Spawn Sender Thread ==========

    // Clone stream for sender thread (allows concurrent read/write)
    let writer = stream.try_clone().expect("clone failed");
    spawn_sender_thread(writer, rx);

    // ========== Main Receive Loop ==========

    // Functional iterator approach instead of explicit loop
    std::iter::from_fn(|| receive_encrypted_message(&mut stream).ok())
        .filter(|msg| !msg.is_empty())  // Skip empty messages
        .try_for_each(|encrypted_msg| {
            // Display encrypted hex for educational purposes (NO DECRYPTION!)
            display_encrypted_hex(&username, &encrypted_msg, ">>>");

            // Relay encrypted message to other clients (NO DECRYPTION!)
            broadcast_to_others(&clients, &username, &encrypted_msg);

            Ok::<(), ()>(())  // Continue iteration
        })
        .ok();  // Ignore final result

    // When loop ends, client has disconnected

    // ========== Cleanup ==========

    // Remove client from map
    clients.lock().unwrap().remove(&username);
    println!("\n<<< {} disconnected", username);

    // ========== Broadcast Leave Message ==========

    // Notify remaining clients that this user left (encrypted system message)
    let leave_msg = create_encrypted_system_message(format!("{} left", username), &key);
    broadcast_to_all(&clients, leave_msg);
}

// ============================================================
// Main entry point
// ============================================================

fn main() -> io::Result<()> {
// Initialize libsodium
sodiumoxide::init().expect("Failed to initialize libsodium");

    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║          Chat Server - Relay-Only Mode                        ║");
    println!("╠════════════════════════════════════════════════════════════════╣");
    println!("║  Port: 5555                                                    ║");
    println!("║  Encryption: ChaCha20-Poly1305 (libsodium)                     ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    // ========== Encryption Key Setup ==========

    println!("⚠️  WARNING: This passphrase must match on ALL clients!");
    println!("For learning: Try 'mysecret123' - all clients must use same phrase.");
    println!();

    // Read passphrase from stdin
    print!("Enter encryption passphrase: ");
    io::stdout().flush()?;

    let mut passphrase = String::new();
    io::stdin().read_line(&mut passphrase)?;
    let passphrase = passphrase.trim();

    // Validate passphrase is not empty
    match passphrase.is_empty() {
        true => {
            eprintln!("Error: Passphrase cannot be empty!");
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Empty passphrase"));
        }
        false => ()
    }

    // Derive encryption key from passphrase
    let key = derive_key_from_passphrase(passphrase);

    println!("✅ Encryption key derived from passphrase");
    println!();
    println!("║  Status: Running - Waiting for connections...                 ║");
    println!("║                                                                ║");
    println!("║  NOTE: Server NEVER decrypts user messages!                    ║");
    println!("║        Messages are relayed in encrypted form.                 ║");
    println!("║        Encrypted hex displayed for educational purposes.       ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    // ========== Server Setup ==========

    // Create shared client map
    // Arc allows multiple threads to own it
    // Mutex ensures only one thread accesses it at a time
    let clients: ClientMap = Arc::new(Mutex::new(HashMap::new()));

    // Bind to all interfaces on port 5555
    let listener = TcpListener::bind("0.0.0.0:5555")?;

    // ========== Accept Connections ==========

    // Functional iterator approach instead of explicit loop
    listener.incoming()  // Iterator over incoming connections
        .filter_map(Result::ok)  // Skip failed connections
        .for_each(|stream| {
            // Clone Arc for this thread (increments reference count)
            let clients = Arc::clone(&clients);
            let key = key.clone();

            // Spawn thread to handle this client
            thread::spawn(move || handle_client(stream, clients, key));
        });

    // Note: This loop never exits unless listener fails
    // In production, you'd want graceful shutdown handling

    Ok(())
}
*/