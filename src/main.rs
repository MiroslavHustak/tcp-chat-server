// ============================================================
// TCP Chat Server - Educational Version
// ============================================================
// This server demonstrates:
// - End-to-end encryption (server relays encrypted messages)
// - Functional programming patterns in Rust (similar to F#)
// - Thread-per-client architecture
// - Message-passing between threads (mpsc channels)
// - Shared state with Arc<Mutex<T>>
// - Iterator-based control flow
//
// IMPORTANT: Server NEVER decrypts messages for relaying!
// Decryption only happens for educational console display.
// In production, remove all decrypt_for_display() calls.
// ============================================================

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

// ============================================================
// Constants
// ============================================================

/// Maximum message size (1 MB) to prevent memory exhaustion attacks
const MAX_MESSAGE_SIZE: usize = 1_000_000;

/// Encryption key - ONLY used for educational display on server console
/// The server does NOT decrypt messages for relaying - only for logging!
const KEY: u8 = 42;

// ============================================================
// Pure utility functions (no I/O, no side effects)
// ============================================================
// These functions are "pure" - they transform data without
// performing I/O or modifying global state.
// Organized in dependency order (F# style).
// ============================================================

/// XOR transformation for encryption/decryption
///
/// XOR is symmetric: xor(xor(data, key), key) == data
/// This is VERY weak encryption - for learning only!
///
/// # Arguments
/// * `data` - Bytes to transform
/// * `key` - Encryption key (single byte)
///
/// # Returns
/// Transformed bytes
fn xor_transform(data: &[u8], key: u8) -> Vec<u8> {
    data.iter()           // Iterator over bytes
        .map(|&b| b ^ key) // XOR each byte with key
        .collect()         // Collect into Vec<u8>
}

/// Convert bytes to hexadecimal string for display
///
/// Example: [72, 101, 108, 108, 111] -> "48 65 6c 6c 6f"
/// Used for displaying encrypted messages in readable format
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))  // Format each byte as 2-digit hex
        .collect::<Vec<_>>()
        .join(" ")  // Join with spaces
}

/// Decrypt bytes for educational display ONLY
///
/// WARNING: This function should ONLY be used for server-side logging!
/// The server should NEVER decrypt messages for relaying to other clients.
///
/// Converts decrypted bytes to String (may contain invalid chars)
fn decrypt_for_display(encrypted: &[u8]) -> String {
    xor_transform(encrypted, KEY)
        .into_iter()
        .map(|b| b as char)  // Convert to char (may be invalid UTF-8!)
        .collect()
}

/// Prepend username to encrypted message
///
/// Creates "username: " prefix, encrypts it, then combines with message.
/// This ensures the entire broadcast (including username) is encrypted.
///
/// # Arguments
/// * `username` - Username to prepend
/// * `encrypted_msg` - Already-encrypted message bytes
///
/// # Returns
/// Combined encrypted bytes: "username: " + message
fn prepend_username(username: &str, encrypted_msg: &[u8]) -> Vec<u8> {
    let prefix = format!("{}: ", username);
    xor_transform(prefix.as_bytes(), KEY)  // Encrypt the prefix
        .into_iter()
        .chain(encrypted_msg.iter().copied())  // Chain with message
        .collect()
}

/// Create encrypted system message (join/leave notifications)
///
/// System messages like "Alice joined" are created by server,
/// so they need to be encrypted before sending to clients.
fn create_system_message(text: String) -> Vec<u8> {
    xor_transform(text.as_bytes(), KEY)
}

// ============================================================
// I/O functions (ordered by dependency)
// ============================================================
// These handle network I/O. Organized so simpler functions
// come first, and more complex functions that use them come later.
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
/// Note: Server does NOT decrypt! Returns encrypted bytes.
/// Uses pattern matching instead of if-else (F# style).
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
/// 2. Send encrypted bytes
/// 3. Flush to ensure immediate sending
///
/// Uses functional chaining with `and_then`
fn send_encrypted_message<W: Write>(writer: &mut W, encrypted: &[u8]) -> io::Result<()> {
    let len = encrypted.len() as u32;
    writer.write_all(&len.to_be_bytes())      // Write length
        .and_then(|_| writer.write_all(encrypted))  // Then write data
        .and_then(|_| writer.flush())          // Then flush
}

// ============================================================
// Display functions
// ============================================================
// Functions for server console output (educational purposes)
// ============================================================

/// Display message in both encrypted (hex) and decrypted forms
///
/// EDUCATIONAL ONLY: Shows what server could see if it decrypted.
/// In production, remove all calls to this function!
///
/// # Arguments
/// * `username` - Username of sender
/// * `encrypted` - Encrypted message bytes
/// * `prefix` - Display prefix (e.g., ">>>")
fn display_encrypted(username: &str, encrypted: &[u8], prefix: &str) {
    println!("{} {}: [ENCRYPTED HEX] {}", prefix, username, bytes_to_hex(encrypted));
    println!("{} {}: [DECRYPTED]     {}", prefix, username, decrypt_for_display(encrypted));
}

// ============================================================
// Type aliases (for clarity and maintainability)
// ============================================================

/// Sender for client's message channel
/// Each client has a channel for receiving broadcast messages
type ClientSender = Sender<Vec<u8>>;

/// Shared map of connected clients
/// Arc = Atomic Reference Counting (thread-safe shared ownership)
/// Mutex = Mutual exclusion lock (only one thread can access at a time)
/// HashMap = username -> sender for that client
type ClientMap = Arc<Mutex<HashMap<String, ClientSender>>>;

// ============================================================
// Business logic functions
// ============================================================
// Functions that implement core chat server logic
// ============================================================

/// Extract username from encrypted data
///
/// Decrypts username ONLY for server-side client tracking.
/// Returns None if username is empty after trimming.
///
/// Uses Option type (like F#) for explicit handling of invalid cases.
fn extract_username(encrypted: &[u8]) -> Option<String> {
    let username = decrypt_for_display(encrypted);
    match username.trim().is_empty() {
        true => None,
        false => Some(username)
    }
}

/// Register a new client in the shared client map
///
/// Thread-safe: Uses Mutex to ensure only one thread modifies map at a time.
///
/// # Arguments
/// * `clients` - Shared client map
/// * `username` - Username to register
/// * `sender` - Channel sender for this client
///
/// # Returns
/// Ok(()) if successful, Err(message) if username already taken
fn register_client(clients: &ClientMap, username: String, sender: ClientSender) -> Result<(), String> {
    let mut map = clients.lock().unwrap();  // Acquire lock (blocks if another thread has it)
    match map.contains_key(&username) {
        true => Err(format!("Username {} already taken", username)),
        false => {
            map.insert(username, sender);
            Ok(())
        }
    }
    // Lock automatically released when `map` goes out of scope
}

/// Broadcast message to all clients except sender
///
/// Uses functional iteration instead of for loops.
/// Filters out sender, then sends to everyone else.
///
/// # Arguments
/// * `clients` - Shared client map
/// * `sender_name` - Username of sender (to exclude)
/// * `message` - Encrypted message to broadcast
fn broadcast_to_others(clients: &ClientMap, sender_name: &str, message: Vec<u8>) {
    clients.lock().unwrap()
        .iter()
        .filter(|(name, _)| *name != sender_name)  // Exclude sender
        .for_each(|(_, sender)| {
            sender.send(message.clone()).ok();  // Send to each client
        });
}

/// Broadcast message to ALL connected clients
///
/// Used for system messages (join/leave notifications).
///
/// # Arguments
/// * `clients` - Shared client map
/// * `message` - Encrypted message to broadcast
fn broadcast_to_all(clients: &ClientMap, message: Vec<u8>) {
    clients.lock().unwrap()
        .values()  // Only need senders, not usernames
        .for_each(|sender| {
            sender.send(message.clone()).ok();
        });
}

// ============================================================
// Thread management
// ============================================================

/// Spawn a thread to send messages to a client
///
/// Each client has TWO threads:
/// 1. Main thread (handle_client): receives messages from client
/// 2. Sender thread (this): sends messages to client
///
/// This separation prevents blocking: receiving can happen
/// while sending is in progress, and vice versa.
///
/// # Arguments
/// * `writer` - TCP stream for writing
/// * `rx` - Channel receiver for messages to send
fn spawn_sender_thread(mut writer: TcpStream, rx: mpsc::Receiver<Vec<u8>>) {
    thread::spawn(move || {
        rx.into_iter()  // Convert receiver to iterator
            // Send each message until error or channel closes
            .try_for_each(|encrypted_msg| send_encrypted_message(&mut writer, &encrypted_msg))
            .ok();  // Ignore result (client disconnected)
    });
}

// ============================================================
// Client handler (uses all above functions)
// ============================================================
// Main function that handles a connected client.
// Runs in its own thread (spawned in main).
// ============================================================

/// Handle a single client connection
///
/// This function:
/// 1. Receives and validates username
/// 2. Registers client in shared map
/// 3. Spawns sender thread for this client
/// 4. Receives messages from client in loop
/// 5. Broadcasts messages to other clients
/// 6. Cleans up on disconnect
///
/// Uses functional patterns throughout (no explicit loops!).
///
/// # Arguments
/// * `stream` - TCP connection to this client
/// * `clients` - Shared map of all connected clients
fn handle_client(mut stream: TcpStream, clients: ClientMap) {
    // ========== Username Setup ==========

    // Receive and validate username using functional composition
    let username = receive_encrypted_message(&mut stream)
        .ok()                                    // Convert Result to Option
        .and_then(|data| extract_username(&data)) // Extract username from encrypted data
        .filter(|name| !name.is_empty());        // Filter out empty names

    let username = match username {
        Some(name) => name,
        None => {
            eprintln!("Failed to receive valid username");
            return;  // Exit handler, connection will close
        }
    };

    println!("\n>>> {} joined", username);

    // ========== Client Registration ==========

    // Create channel for sending messages to this client
    let (tx, rx) = mpsc::channel::<Vec<u8>>();

    // Register client (pattern matching for error handling)
    match register_client(&clients, username.clone(), tx) {
        Err(e) => {
            eprintln!("{}", e);
            return;  // Username taken, close connection
        }
        Ok(_) => ()  // Success, continue
    }

    // ========== Broadcast Join Message ==========

    // Notify other clients that this user joined
    let join_msg = create_system_message(format!("{} joined", username));
    broadcast_to_others(&clients, &username, join_msg);

    // ========== Spawn Sender Thread ==========

    // Clone stream for sender thread (allows concurrent read/write)
    let writer = stream.try_clone().expect("clone failed");
    spawn_sender_thread(writer, rx);

    // ========== Main Receive Loop ==========

    // Functional iterator approach instead of explicit loop
    std::iter::from_fn(|| receive_encrypted_message(&mut stream).ok())
        .filter(|msg| !msg.is_empty())  // Skip empty messages
        .try_for_each(|encrypted_msg| {
            // Display for educational purposes (REMOVE IN PRODUCTION!)
            display_encrypted(&username, &encrypted_msg, ">>>");

            // Relay encrypted message with username prefix
            let broadcast = prepend_username(&username, &encrypted_msg);
            broadcast_to_others(&clients, &username, broadcast);

            Ok::<(), ()>(())  // Continue iteration
        })
        .ok();  // Ignore final result

    // When loop ends, client has disconnected

    // ========== Cleanup ==========

    // Remove client from map
    clients.lock().unwrap().remove(&username);
    println!("\n<<< {} disconnected", username);

    // ========== Broadcast Leave Message ==========

    // Notify remaining clients that this user left
    let leave_msg = create_system_message(format!("{} left", username));
    broadcast_to_all(&clients, leave_msg);
}

// ============================================================
// Main entry point
// ============================================================
// Sets up server and spawns thread for each incoming connection
// ============================================================

fn main() -> io::Result<()> {
    // ========== Server Setup ==========

    // Create shared client map
    // Arc allows multiple threads to own it
    // Mutex ensures only one thread accesses it at a time
    let clients: ClientMap = Arc::new(Mutex::new(HashMap::new()));

    // Bind to all interfaces on port 5555
    let listener = TcpListener::bind("0.0.0.0:5555")?;

    // ========== Display Banner ==========

    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║          Chat Server - Educational Mode                       ║");
    println!("╠════════════════════════════════════════════════════════════════╣");
    println!("║  Port: 5555                                                    ║");
    println!("║  Status: Running                                               ║");
    println!("║                                                                ║");
    println!("║  NOTE: Messages displayed in both ENCRYPTED and DECRYPTED      ║");
    println!("║        forms for educational purposes only.                    ║");
    println!("║        In production, server should NEVER see plaintext!       ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    // ========== Accept Connections ==========

    // Functional iterator approach instead of explicit loop
    listener.incoming()  // Iterator over incoming connections
        .filter_map(Result::ok)  // Skip failed connections
        .for_each(|stream| {
            // Clone Arc for this thread (increments reference count)
            let clients = Arc::clone(&clients);

            // Spawn thread to handle this client
            thread::spawn(move || handle_client(stream, clients));
        });

    // Note: This loop never exits unless listener fails
    // In production, you'd want graceful shutdown handling

    Ok(())
}