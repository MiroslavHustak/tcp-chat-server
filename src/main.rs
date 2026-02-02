use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

const MAX_MESSAGE_SIZE: usize = 1_000_000; // 1 MB
const KEY: u8 = 42; // Only for educational display

// ============================================================
// Pragmatically pure utility functions (no I/O, no side effects)
// ============================================================

fn xor_transform(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|&b| b ^ key).collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

fn decrypt_for_display(encrypted: &[u8]) -> String {
    xor_transform(encrypted, KEY)
        .into_iter()
        .map(|b| b as char)
        .collect()
}

fn prepend_username(username: &str, encrypted_msg: &[u8]) -> Vec<u8> {
    let prefix = format!("{}: ", username);
    xor_transform(prefix.as_bytes(), KEY)
        .into_iter()
        .chain(encrypted_msg.iter().copied())
        .collect()
}

fn create_system_message(text: String) -> Vec<u8> {
    xor_transform(text.as_bytes(), KEY)
}

// ============================================================
// I/O functions (ordered by dependency)
// ============================================================

fn read_message_length<R: Read>(reader: &mut R) -> io::Result<usize> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    Ok(u32::from_be_bytes(len_buf) as usize)
}

fn read_encrypted_bytes<R: Read>(reader: &mut R, len: usize) -> io::Result<Vec<u8>> {
    let mut encrypted = vec![0u8; len];
    reader.read_exact(&mut encrypted)?;
    Ok(encrypted)
}

fn receive_encrypted_message<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let len = read_message_length(reader)?;

    match len <= MAX_MESSAGE_SIZE {
        false => Err(io::Error::new(io::ErrorKind::InvalidData, "Message too large")),
        true => read_encrypted_bytes(reader, len)
    }
}

fn send_encrypted_message<W: Write>(writer: &mut W, encrypted: &[u8]) -> io::Result<()> {
    let len = encrypted.len() as u32;
    writer.write_all(&len.to_be_bytes())
        .and_then(|_| writer.write_all(encrypted))
        .and_then(|_| writer.flush())
}

// ============================================================
// Display functions
// ============================================================

fn display_encrypted(username: &str, encrypted: &[u8], prefix: &str) {
    println!("{} {}: [ENCRYPTED HEX] {}", prefix, username, bytes_to_hex(encrypted));
    println!("{} {}: [DECRYPTED]     {}", prefix, username, decrypt_for_display(encrypted));
}

// ============================================================
// Type aliases (for clarity)
// ============================================================

type ClientSender = Sender<Vec<u8>>;
type ClientMap = Arc<Mutex<HashMap<String, ClientSender>>>;

// ============================================================
// Business logic functions
// ============================================================

fn extract_username(encrypted: &[u8]) -> Option<String> {
    let username = decrypt_for_display(encrypted);
    match username.trim().is_empty() {
        true => None,
        false => Some(username)
    }
}

fn register_client(clients: &ClientMap, username: String, sender: ClientSender) -> Result<(), String> {
    let mut map = clients.lock().unwrap();
    match map.contains_key(&username) {
        true => Err(format!("Username {} already taken", username)),
        false => {
            map.insert(username, sender);
            Ok(())
        }
    }
}

fn broadcast_to_others(clients: &ClientMap, sender_name: &str, message: Vec<u8>) {
    clients.lock().unwrap()
        .iter()
        .filter(|(name, _)| *name != sender_name)
        .for_each(|(_, sender)| {
            sender.send(message.clone()).ok();
        });
}

fn broadcast_to_all(clients: &ClientMap, message: Vec<u8>) {
    clients.lock().unwrap()
        .values()
        .for_each(|sender| {
            sender.send(message.clone()).ok();
        });
}

// ============================================================
// Thread management
// ============================================================

fn spawn_sender_thread(mut writer: TcpStream, rx: mpsc::Receiver<Vec<u8>>) {
    thread::spawn(move || {
        rx.into_iter()
            .try_for_each(|encrypted_msg| send_encrypted_message(&mut writer, &encrypted_msg))
            .ok();
    });
}

// ============================================================
// Client handler (uses all above functions)
// ============================================================

fn handle_client(mut stream: TcpStream, clients: ClientMap) {
    // Receive and validate username
    let username = receive_encrypted_message(&mut stream)
        .ok()
        .and_then(|data| extract_username(&data))
        .filter(|name| !name.is_empty());

    let username = match username {
        Some(name) => name,
        None => {
            eprintln!("Failed to receive valid username");
            return;
        }
    };

    println!("\n>>> {} joined", username);

    // Create channel and register client - PATTERN MATCHED VERSION
    let (tx, rx) = mpsc::channel::<Vec<u8>>();

    match register_client(&clients, username.clone(), tx) {
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
        Ok(_) => ()
    }

    // Broadcast join message
    let join_msg = create_system_message(format!("{} joined", username));
    broadcast_to_others(&clients, &username, join_msg);

    // Spawn sender thread
    let writer = stream.try_clone().expect("clone failed");
    spawn_sender_thread(writer, rx);

    // Main receive loop - functional style
    std::iter::from_fn(|| receive_encrypted_message(&mut stream).ok())
        .filter(|msg| !msg.is_empty())
        .try_for_each(|encrypted_msg| {
            // Display encrypted and decrypted for educational purposes
            display_encrypted(&username, &encrypted_msg, ">>>");

            // Relay encrypted message with username prefix
            let broadcast = prepend_username(&username, &encrypted_msg);
            broadcast_to_others(&clients, &username, broadcast);

            Ok::<(), ()>(())
        })
        .ok();

    // Cleanup on disconnect
    clients.lock().unwrap().remove(&username);
    println!("\n<<< {} disconnected", username);

    // Broadcast leave message
    let leave_msg = create_system_message(format!("{} left", username));
    broadcast_to_all(&clients, leave_msg);
}

// ============================================================
// Main entry point
// ============================================================

fn main() -> io::Result<()> {
    let clients: ClientMap = Arc::new(Mutex::new(HashMap::new()));

    let listener = TcpListener::bind("0.0.0.0:5555")?;

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

    listener.incoming()
        .filter_map(Result::ok)
        .for_each(|stream| {
            let clients = Arc::clone(&clients);
            thread::spawn(move || handle_client(stream, clients));
        });

    Ok(())
}