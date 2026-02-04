// ============================================================
// Chat Server
// ============================================================
// Characteristics:
// - NEVER decrypts chat messages
// - Encrypts system messages ONLY
// - Relays ciphertext verbatim
// - NO ciphertext concatenation
// - Iterator-based receive loop
// ============================================================

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::hash::sha256;

// ============================================================
// Utilities
// ============================================================

fn derive_key_from_passphrase(passphrase: &str) -> secretbox::Key {
    let hash = sha256::hash(passphrase.as_bytes());
    secretbox::Key::from_slice(&hash.0)
        .expect("SHA-256 always produces 32 bytes")
}

fn read_message_length<R: Read>(reader: &mut R) -> io::Result<usize> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf) as usize)
}

fn receive_encrypted_message<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let len = read_message_length(reader)?;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn send_encrypted_message<W: Write>(writer: &mut W, encrypted: &[u8]) -> io::Result<()> {
    writer.write_all(&(encrypted.len() as u32).to_be_bytes())
        .and_then(|_| writer.write_all(encrypted))
        .and_then(|_| writer.flush())
}

fn decrypt_username(encrypted: &[u8], key: &secretbox::Key) -> Option<String> {
    match encrypted.len() < secretbox::NONCEBYTES {
        true => None,
        false => {
            let nonce = secretbox::Nonce::from_slice(&encrypted[..secretbox::NONCEBYTES])?;
            let ciphertext = &encrypted[secretbox::NONCEBYTES..];

            secretbox::open(ciphertext, &nonce, key)
                .ok()
                .and_then(|p| String::from_utf8(p).ok())
        }
    }
}

fn encrypt_system_message(text: &str, key: &secretbox::Key) -> Vec<u8> {
    let nonce = secretbox::gen_nonce();
    let ciphertext = secretbox::seal(text.as_bytes(), &nonce, key);

    let mut msg = nonce.0.to_vec();
    msg.extend_from_slice(&ciphertext);
    msg
}

// ============================================================
// Types
// ============================================================

type ClientSender = mpsc::Sender<Vec<u8>>;
type ClientMap = Arc<Mutex<HashMap<String, ClientSender>>>;

// ============================================================
// Client handler
// ============================================================

fn handle_client(mut stream: TcpStream, clients: ClientMap, key: secretbox::Key) {
    // ===== Receive encrypted username =====
    let username = receive_encrypted_message(&mut stream)
        .ok()
        .and_then(|msg| decrypt_username(&msg, &key));

    let username = match username {
        Some(name) => name,
        None => return,
    };

    println!(">>> {} joined", username);

    let (tx, rx) = mpsc::channel();
    clients.lock().unwrap().insert(username.clone(), tx);

    // ===== Sender thread =====
    let mut writer = stream.try_clone().expect("clone failed");
    thread::spawn(move || {
        rx.into_iter()
            .try_for_each(|msg| send_encrypted_message(&mut writer, &msg))
            .ok();
    });

    // ===== Broadcast join =====
    let join = encrypt_system_message(&format!("{} joined", username), &key);
    clients.lock().unwrap()
        .values()
        .for_each(|tx| { tx.send(join.clone()).ok(); });

    // ===== Receive loop =====
    std::iter::from_fn(|| receive_encrypted_message(&mut stream).ok())
        .for_each(|encrypted| {
            clients.lock().unwrap()
                .iter()
                .filter(|(name, _)| *name != &username)
                .for_each(|(_, tx)| {
                    tx.send(encrypted.clone()).ok();
                });
        });

    // ===== Cleanup =====
    clients.lock().unwrap().remove(&username);
    println!("<<< {} left", username);

    let leave = encrypt_system_message(&format!("{} left", username), &key);
    clients.lock().unwrap()
        .values()
        .for_each(|tx| { tx.send(leave.clone()).ok(); });
}

// ============================================================
// Main
// ============================================================

fn main() -> io::Result<()> {
    sodiumoxide::init().expect("libsodium init failed");

    print!("Enter encryption passphrase: ");
    io::stdout().flush()?;

    let mut passphrase = String::new();
    io::stdin().read_line(&mut passphrase)?;
    let key = derive_key_from_passphrase(passphrase.trim());

    let listener = TcpListener::bind("0.0.0.0:5555")?;
    let clients: ClientMap = Arc::new(Mutex::new(HashMap::new()));

    listener.incoming()
        .filter_map(Result::ok)
        .for_each(|stream| {
            let clients = Arc::clone(&clients);
            let key = key.clone();
            thread::spawn(move || handle_client(stream, clients, key));
        });

    Ok(())
}