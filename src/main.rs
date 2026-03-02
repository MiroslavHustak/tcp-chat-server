
// cargo build --release
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::pwhash;

type ClientSender = mpsc::Sender<Vec<u8>>;  //a type alias
type ClientMap = Arc<Mutex<HashMap<String, ClientSender>>>;  //a type alias

// ============================================================
// Client handler — all protocol logic lives here
// ============================================================
fn handle_client(
    mut stream: TcpStream,
    clients: ClientMap,
    key: secretbox::Key,
    salt: pwhash::Salt,
) -> () {
    fn send_salt(writer: &mut impl Write, salt: &pwhash::Salt) -> io::Result<()> {
        writer.write_all(&salt.0).and_then(|_| writer.flush())
    }

    fn read_message(reader: &mut impl Read) -> io::Result<Vec<u8>> {

        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;

        let mut buf = vec![0u8; u32::from_be_bytes(len_buf) as usize];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn send_message(writer: &mut impl Write, data: &[u8]) -> io::Result<()> {
        writer
            .write_all(&(data.len() as u32).to_be_bytes())
            .and_then(|_| writer.write_all(data))
            .and_then(|_| writer.flush())
    }

    fn decrypt_username(encrypted: &[u8], key: &secretbox::Key) -> Option<String> {
        let nonce = secretbox::Nonce::from_slice(encrypted.get(..secretbox::NONCEBYTES)?)?;

        secretbox::open(&encrypted[secretbox::NONCEBYTES..], &nonce, key)
            .ok()
            .and_then(|p| String::from_utf8(p).ok())
    }

    fn encrypt_system_message(text: &str, key: &secretbox::Key) -> Vec<u8> {
        let nonce = secretbox::gen_nonce();
        let mut msg = nonce.0.to_vec();
        msg.extend_from_slice(&secretbox::seal(text.as_bytes(), &nonce, key));
        msg
    }

    match send_salt(&mut stream, &salt) {
        Err(_) => {println!("Failed to send salt, client abandoned");} // failed to send salt — abandon client
        Ok(()) => {
            let username = match read_message(&mut stream)
                .ok()
                .and_then(|msg| decrypt_username(&msg, &key))

            {
                Some(name) => name,
                None => return,
            };

            println!(">>> {} joined", username);

            let (tx, rx) = mpsc::channel::<Vec<u8>>();
            clients.lock().unwrap().insert(username.clone(), tx);

            let mut writer = stream.try_clone().expect("clone failed");
            thread::spawn(move || {
                rx.into_iter()
                    .try_for_each(|msg| send_message(&mut writer, &msg))
                    .ok();
            });

            thread::sleep(std::time::Duration::from_millis(100));

            let join_msg = encrypt_system_message(&format!("{} joined", username), &key);
            clients
                .lock()
                .unwrap()
                .values()
                .for_each(|tx| { tx.send(join_msg.clone()).ok(); });

            std::iter::from_fn(|| read_message(&mut stream).ok())
                .for_each(|encrypted| {
                    clients
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .iter()
                        .filter(|(name, _)| *name != &username)
                        .for_each(|(_, tx)| { tx.send(encrypted.clone()).ok(); });
                });

            clients
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&username);

            println!("<<< {} left", username);

            let leave_msg = encrypt_system_message(&format!("{} left", username), &key);
            clients
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .values()
                .for_each(|tx| { tx.send(leave_msg.clone()).ok(); });
        }
    }
}

// ============================================================
// Main — startup, key derivation, accept loop
// ============================================================
fn main() -> io::Result<()> {
    fn prompt_passphrase() -> io::Result<String> {
        print!("Enter encryption passphrase: ");
        io::stdout().flush()?;
        let mut s = String::new();
        io::stdin().read_line(&mut s)?;
        Ok(s.trim().to_owned())
    }

    fn derive_key(passphrase: &str, salt: &pwhash::Salt) -> secretbox::Key {
        let mut key_bytes = [0u8; secretbox::KEYBYTES];
        pwhash::derive_key(
            &mut key_bytes,
            passphrase.as_bytes(),
            salt,
            pwhash::OPSLIMIT_INTERACTIVE, // ~0.5 seconds on modern hardware
            pwhash::MEMLIMIT_INTERACTIVE,  // ~64 MB RAM — too costly to brute-force
        )
            .expect("Argon2 key derivation failed");
        secretbox::Key(key_bytes)
    }

    sodiumoxide::init().expect("libsodium init failed");

    let passphrase = prompt_passphrase()?;

    let salt = pwhash::gen_salt();

    println!("Deriving key (Argon2id)...");
    let key = derive_key(&passphrase, &salt);

    println!("Key ready. Listening on 0.0.0.0:5555");
    let listener = TcpListener::bind("0.0.0.0:5555")?;
    println!(">>> TCP chat listening on 0.0.0.0:5555");
    println!(">>> Waiting for connections...");

    let clients: ClientMap = Arc::new(Mutex::new(HashMap::new()));

    listener
        .incoming()
        .filter_map(Result::ok)
        .for_each(|stream| {
            let clients = Arc::clone(&clients);
            let key = key.clone();
            let salt = salt.clone();
            thread::spawn(move || handle_client(stream, clients, key, salt));
        });

    Ok(())
}