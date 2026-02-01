use std::collections::HashMap;
use std::io::{Read, Write};
use std::io::{self, ErrorKind};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

/// ===============================
/// Core byte-stream abstractions
/// ===============================

/// Plain (unencrypted) byte stream.
///
/// Owns:
/// - data buffer
/// - read cursor
///
/// Mutability is external (`&mut self`)
pub struct PlainBytes {
    bytes: Vec<u8>,
    pos: usize,
}

/// Encrypted byte stream.
///
/// Encryption is lazy:
/// XOR happens on read, not upfront.
#[derive(Clone)]
pub struct EncryptedBytes {
    bytes: Vec<u8>,
    pos: usize,
    key: u8,
}

impl PlainBytes {
    pub fn read(&mut self) -> Option<u8> {
        if self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            self.pos += 1;
            Some(b)
        } else {
            None
        }
    }

    pub fn read_all(mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(b) = self.read() {
            out.push(b);
        }
        out
    }

    pub fn encrypt(self, key: u8) -> EncryptedBytes {
        EncryptedBytes {
            bytes: self.bytes,
            pos: 0,
            key,
        }
    }
}

impl EncryptedBytes {
    pub fn read(&mut self) -> Option<u8> {
        if self.pos < self.bytes.len() {
            let b = self.bytes[self.pos] ^ self.key;
            self.pos += 1;
            Some(b)
        } else {
            None
        }
    }

    pub fn read_all(mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(b) = self.read() {
            out.push(b);
        }
        out
    }

    pub fn decrypt(self, key: u8) -> Result<PlainBytes, EncryptedBytes> {
        if self.key == key {
            Ok(PlainBytes {
                bytes: self.bytes,
                pos: 0,
            })
        } else {
            Err(self)
        }
    }
}

/// ===============================
/// Framing helpers (TCP-safe)
/// ===============================

fn send_message(stream: &mut TcpStream, encrypted: EncryptedBytes) -> std::io::Result<()> {
    let payload = encrypted.read_all();
    let len = payload.len() as u32;

    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&payload)?;
    Ok(())
}

fn receive_message(stream: &mut TcpStream, key: u8) -> std::io::Result<String> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;

    let encrypted = EncryptedBytes {
        bytes: payload,
        pos: 0,
        key,
    };

    let plain = match encrypted.decrypt(key) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Received message with invalid key");
            return Err(io::Error::new(ErrorKind::InvalidData, "Invalid encryption key"));
        }
    };

    let bytes = plain.read_all();
    Ok(String::from_utf8(bytes).unwrap())
}

/// ===============================
/// Chat server
/// ===============================

type Clients = Arc<Mutex<HashMap<String, TcpStream>>>;

fn handle_client(mut stream: TcpStream, clients: Clients, key: u8) {
    // First message = username
    let username = match receive_message(&mut stream, key) {
        Ok(u) => u,
        Err(_) => return,
    };

    println!("{} joined", username);

    clients
        .lock()
        .unwrap()
        .insert(username.clone(), stream.try_clone().unwrap());

    loop {
        let msg = match receive_message(&mut stream, key) {
            Ok(m) => m,
            Err(_) => break,
        };

        println!("{}: {}", username, msg);

        let response =
            PlainBytes { bytes: format!("{}: {}", username, msg).into_bytes(), pos: 0 }
                .encrypt(key);

        let clients = clients.lock().unwrap();
        for (name, client) in clients.iter() {
            if name != &username {
                let _ = send_message(&mut client.try_clone().unwrap(), response.clone());
            }
        }
    }

    clients.lock().unwrap().remove(&username);
    println!("{} disconnected", username);
}

fn main() {
    let key = 42;
    let clients: Clients = Arc::new(Mutex::new(HashMap::new()));

    let listener = TcpListener::bind("0.0.0.0:5555").expect("bind failed");
    println!("Chat server running on port 5555");

    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            let clients = Arc::clone(&clients);
            thread::spawn(move || handle_client(stream, clients, key));
        }
    }
} 