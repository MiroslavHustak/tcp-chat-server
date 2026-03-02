

// ============================================================
// Chat Server
// ============================================================
// Characteristics:
// - NEVER decrypts chat messages
// - Encrypts system messages ONLY
// - Relays ciphertext verbatim
// - NO ciphertext concatenation
// - Iterator-based receive loop
// - Argon2 key derivation with random salt
// - Salt is generated once at startup and sent to each client
//   in plaintext before any encrypted traffic begins
// ============================================================
// cargo build --release
// HashMap - key-value map for storing client connections
use std::collections::HashMap;

// - io::Result, io::Error for error handling
// - Read trait: read bytes from streams
// - Write trait: write bytes to streams, flush buffers
use std::io::{self, Read, Write};

// TCP networking primitives
// - TcpListener: accepts incoming TCP connections on a port
// - TcpStream: bidirectional TCP connection to/from a client
use std::net::{TcpListener, TcpStream};

// Thread-safe synchronization primitives
// - Arc: Atomic Reference Counter - shared ownership across threads
// - Mutex: Mutual exclusion lock - safe mutable access from multiple threads
// - mpsc: Multi-Producer Single-Consumer channels for thread communication
use std::sync::{Arc, Mutex, mpsc};

// Thread spawning and management
// Used to create background threads for handling clients
use std::thread;

// XSalsa20-Poly1305 authenticated encryption (secretbox)
// - seal(): encrypt plaintext -> ciphertext
// - open(): decrypt ciphertext -> plaintext
// - gen_nonce(): generate random nonce for each message
use sodiumoxide::crypto::secretbox;

// Argon2id password hashing / key derivation
// - derive_key(): convert passphrase + salt -> encryption key
// - gen_salt(): generate random salt
// - OPSLIMIT/MEMLIMIT: tuning parameters for security vs speed
use sodiumoxide::crypto::pwhash;

//A channel sender that sends Vec<u8> (byte arrays)
type ClientSender = mpsc::Sender<Vec<u8>>; //a type alias

// Wrapped in Mutex for thread safety:
// Wrapped in Arc for shared ownership:
// Only one thread can access the HashMap at a time
type ClientMap = Arc<Mutex<HashMap<String, ClientSender>>>; //a type alias

// ============================================================
// Client handler — all protocol logic lives here
// ============================================================
fn handle_client(
    mut stream: TcpStream,
    clients: ClientMap,
    key: secretbox::Key,
    salt: pwhash::Salt,
) -> () {
    //-> () does not have to be here as it's the default
    /// Sends the raw salt bytes to the client in plaintext.
    /// Salt is not secret — it just needs to reach the client before
    /// any encrypted traffic so both sides derive the same key.
    /// Salt = Random data added to a password/input before hashing/key derivation
    /// impl Write — "any type that implements the Write trait" Could be TcpStream, File, Vec<u8>, Stdout, etc.
    /// This is generic without using explicit generic syntax
    /*
    // Inside sodiumoxide library (roughly):
    pub struct Salt(pub [u8; SALTBYTES]);
    //              ^^^                   ↑
    //              |                     └─ Fixed-size array of bytes
    //              └─ Tuple struct with one field
    */
    fn send_salt(writer: &mut impl Write, salt: &pwhash::Salt) -> io::Result<()> {
        writer.write_all(&salt.0).and_then(|_| writer.flush())
        //and_then = Result.bind or Option.bind
    }

    fn read_message(reader: &mut impl Read) -> io::Result<Vec<u8>> {
        // Fixed array — size must be known at COMPILE TIME:
        let mut len_buf = [0u8; 4]; //Create an array of 4 elements, all initialized to 0, all of type u
        // let mut len_buf = [0u8, 0u8, 0u8, 0u8]
        reader.read_exact(&mut len_buf)?;
        // Vec — size can be determined at RUNTIME:
        let mut buf = vec![0u8; u32::from_be_bytes(len_buf) as usize];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }
    /*
    ## Why not just one buffer?

    **TCP is a stream — it has no concept of "message boundaries":**
    ```
    Without length prefix:
    [h][e][l][l][o][w][o][r][l][d]
    ↑
    Where does message 1 end and message 2 begin?
    No way to know!

    With length prefix:
    [0][0][0][5][h][e][l][l][o][0][0][0][5][w][o][r][l][d]
     ↑ length=5  ↑ 5 bytes   ↑ length=5  ↑ 5 bytes
     Message 1                Message 2

    let readMessage (reader: System.IO.Stream) : Result<byte[], exn> =
        result
            {
                let lenBuf = Array.zeroCreate<byte> 4
                do! readExact reader lenBuf  // ← Like ?
                let len = BitConverter.ToUInt32(lenBuf, 0) |> int
                let buf = Array.zeroCreate<byte> len
                do! readExact reader buf  // ← Like ?
                return buf  // ← Only reached if both reads succeeded
            }
    */

    fn send_message(writer: &mut impl Write, data: &[u8]) -> io::Result<()> {
        writer
            .write_all(&(data.len() as u32).to_be_bytes())
            .and_then(|_| writer.write_all(data))
            .and_then(|_| writer.flush()) //and_then = Result.bind or Option.bind

        /*
        F# pseudocode
        writer.writeAll(lengthBytes)
        |> Result.bind (fun _ -> writer.writeAll(data))
        |> Result.bind (fun _ -> writer.flush())
        or
        result
            {
                do! writer.writeAll(lengthBytes)
                do! writer.writeAll(data)
                return! writer.flush()
            }
         */
    }

    fn decrypt_username(encrypted: &[u8], key: &secretbox::Key) -> Option<String> {
        let nonce = secretbox::Nonce::from_slice(encrypted.get(..secretbox::NONCEBYTES)?)?;
        /*
        encrypted.get(..NONCEBYTES) — safely slice the first N bytes, returns Option<&[u8]> (won't panic if too short)
        ? — if that slice doesn't exist (buffer too short), return None early
        Nonce::from_slice(...) — parse those bytes as a nonce, returns Option<Nonce>
            ? — if parsing failed, return None early

        So the nonce is the first chunk of the encrypted buffer. The rest is the actual ciphertext.
        */
        secretbox::open(&encrypted[secretbox::NONCEBYTES..], &nonce, key)
            .ok() //Result.toOption
            .and_then(|p| String::from_utf8(p).ok()) //and again Result.toOption
        //Take everything after the nonce bytes and attempt to decrypt it

        /*
         option //F# pseudocode
             {
                let! nonceBytes = safeSlice encrypted 0 NONCE_SIZE  // get(..NONCEBYTES)?
                let! nonce = Nonce.fromSlice nonceBytes              // Nonce::from_slice(...)?

                let ciphertext = encrypted[NONCE_SIZE..]
                let! plaintext = secretbox.open(ciphertext, nonce, key) |> Result.toOption  // .ok()

                return! String.fromUtf8(plaintext) |> Result.toOption       // .and_then(|p| ...)
            }
        */
    }

    /// Encrypts a plaintext string using symmetric authenticated encryption (NaCl secretbox).
    /// Returns a single byte vector containing the nonce prepended to the ciphertext,
    /// so the receiver can extract the nonce and decrypt.
    fn encrypt_system_message(text: &str, key: &secretbox::Key) -> Vec<u8> {
        // Generate a random one-time nonce (number used once) for this encryption
        let nonce = secretbox::gen_nonce();

        // Start the output buffer with the raw nonce bytes (needed for decryption later)
        let mut msg = nonce.0.to_vec();

        // Encrypt the text and append the ciphertext (+ auth tag) after the nonce
        msg.extend_from_slice(&secretbox::seal(text.as_bytes(), &nonce, key));

        msg
    }

    /*
    let encryptSystemMessage (text: string) (key: SecretboxKey) : byte[] =
        // Generate a random nonce
        let nonce = Secretbox.genNonce()

        // Encrypt the plaintext using the key and nonce
        let ciphertext = Secretbox.seal (Encoding.UTF8.GetBytes text) nonce key

        // Prepend the nonce bytes to the ciphertext and return
        Array.append nonce.Bytes ciphertext
    */

    // ── Salt handshake ──────────────────────────────────────
    // Must happen before any encrypted traffic so the client
    // can derive the same key from the shared passphrase.
    /*
    match send_salt(&mut stream, &salt) {
        Ok(()) => {
            // Salt was sent successfully — continue handling this client
        }
        Err(_) => {
            // Something went wrong (client disconnected, network error, etc.)
            // Abandon this client entirely
            return;
        }
    }

    // ── Receive + decrypt username ──────────────────────────
    let username = match read_message(&mut stream)
        .ok()
        .and_then(|msg| decrypt_username(&msg, &key))
    {
        Some(name) => name,
        None => return,
    };

    println!(">>> {} joined", username);

    // ── Register client, spin up sender thread ──────────────
    // Each client gets a channel. The sender thread drains it,
    // writing every queued message to the TCP stream.
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    clients.lock().unwrap().insert(username.clone(), tx);

    let mut writer = stream.try_clone().expect("clone failed");
    thread::spawn(move || {
        rx.into_iter()
            .try_for_each(|msg| send_message(&mut writer, &msg))
            .ok();
    });

    // Brief pause so the sender thread is ready before the
    // join broadcast below hits the channel.
    thread::sleep(std::time::Duration::from_millis(100));

    // ── Broadcast join notice ───────────────────────────────
    // System messages are encrypted by the server; chat
    // messages are relayed as opaque ciphertext (never touched).
    let join_msg = encrypt_system_message(&format!("{} joined", username), &key);
    clients
        .lock()
        .unwrap()
        .values()
        .for_each(|tx| { tx.send(join_msg.clone()).ok(); });

    // ── Relay loop: forward ciphertext verbatim ─────────────
    // The server never decrypts chat messages — it reads each
    // framed blob and fans it out to every other connected client.
    std::iter::from_fn(|| read_message(&mut stream).ok())
        .for_each(|encrypted| {
            clients
                .lock()
                .unwrap()
                .iter()
                .filter(|(name, _)| *name != &username)
                .for_each(|(_, tx)| { tx.send(encrypted.clone()).ok(); });
        });

    // ── Cleanup + broadcast leave notice ───────────────────
    // Remove the client from the map first so the leave message
    // is not echoed back to the departing client's (now closed) stream.
    clients.lock().unwrap().remove(&username);
    println!("<<< {} left", username);

    let leave_msg = encrypt_system_message(&format!("{} left", username), &key);
    clients
        .lock()
        .unwrap()
        .values()
        .for_each(|tx| { tx.send(leave_msg.clone()).ok(); });
     */
    //the code above using <<return>> works in Rust but not in F#. Here is the F#-yfied version:
    match send_salt(&mut stream, &salt) {
        Err(_) => {println!("Failed to send salt, client abandoned");} // failed to send salt — abandon client
        Ok(()) => {
            // ── Receive + decrypt username ──────────────────────────
            let username = match read_message(&mut stream)
                .ok() //the Result → Option conversion) happens before .and_then
                //implicit Result.toOption
                .and_then(|msg| decrypt_username(&msg, &key)) //Option.bind(fun msg -> decrypt_username msg key)

            //the following code is just part of username
            //a very specific Rust pattern called "let-else" or "unwrapping into a binding" - looks like function Some name -> name | None -> ...
            {
                Some(name) => name,
                None => return, //return never produces a value, so Rust's type checker accepts it in any branch regardless of what type the other branches produce.
            };

            println!(">>> {} joined", username);

            // ── Register client, spin up sender thread ──────────────
            // Each client gets a channel. The sender thread drains it,
            // writing every queued message to the TCP stream.
            let (tx, rx) = mpsc::channel::<Vec<u8>>();
            clients.lock().unwrap().insert(username.clone(), tx);
            /*
            Each client is effectively an actor
            The mpsc channel is the mailbox
            The tx handle stored in the HashMap is how other actors "address" this one
            The sender thread is the actor's processing loop, handling messages one at a time

            Why <Vec<u8>>?
            This is Rust's turbofish syntax for specifying generic type parameters. channel() is a generic function — it can create a channel for any type. But Rust needs to know which type at compile time.
            rustfn channel<T>() -> (Sender<T>, Receiver<T>)
            So channel::<Vec<u8>>() is you telling the compiler: "I want a channel that carries Vec<u8> values." The <Vec<u8>> is slotted between the function name and the parentheses — hence the nickname "turbofish" (::<> looks like a fish).
            You could often omit it and let Rust infer the type from context, but when inference isn't possible, you must be explicit.

            Equivalent F# Code
            F# uses MailboxProcessor for this pattern, which is its native actor model construct:
            let inbox = MailboxProcessor<byte[]>.Start(fun agent ->
                let rec loop () = async {
                    let! msg = agent.Receive()
                    stream.Write(msg, 0, msg.Length)
                    return! loop ()
                }
                loop ()
            )

            clients[username] <- inbox.Post
            The parallels are direct:

            MailboxProcessor<byte[]> ↔ the channel typed as Vec<u8>
            agent.Receive() ↔ rx.recv() — blocking wait for next message
            inbox.Post ↔ tx — the handle you give to others to send messages
            The rec loop ↔ the sender thread's while loop

            Calling channel() returns a matched pair:

            tx — the transmitter (sender side). You clone this and hand it to anyone who wants to send a message to this client.
            rx — the receiver (consumer side). Only the sender thread holds this.

            - **`clients`** is likely an `Arc<Mutex<HashMap<String, Sender<Vec<u8>>>>>`— a shared map of all connected users, protected by a mutex so multiple threads can safely access it.
            - **`.lock()`** acquires the mutex lock. Only one thread can hold this at a time, preventing data races.
            - **`.unwrap()`** handles the `Result` — if the mutex is *poisoned* (a thread panicked while holding it), this would panic too.
            - **`.insert(username.clone(), tx)`** adds this client's username and their `tx` channel handle into the map.

            */

            /*
            try_clone() duplicates the TCP socket at the OS level.
            Both stream and writer point to the same underlying TCP connection, but are now two separate handles.
            Spawns a new thread. The move keyword transfers ownership of writer and rx into the closure — the spawned thread owns them exclusively, which satisfies Rust's borrow checker.
            ### The Architecture This Creates
            ```
            Other clients
                 │
                 │  tx.send(msg)          rx.into_iter()
                 └──────────────► [channel] ──────────────► writer thread ──► TCP socket
                                                                                    ║
            main client thread ◄──────────────────────────────────────────────────╝
            (read_message loop)
            The channel acts as the mailbox (exactly like an F# MailboxProcessor). Any thread can drop a message in via tx.send() without caring about timing.
            The writer thread drains the mailbox sequentially, ensuring messages don't get interleaved on the wire.
            */
            let mut writer = stream.try_clone().expect("clone failed");
            thread::spawn(move || {
                rx.into_iter()
                    .try_for_each(|msg| send_message(&mut writer, &msg))
                    .ok();
            });

            // Brief pause so the sender thread is ready before the
            // join broadcast below hits the channel.
            thread::sleep(std::time::Duration::from_millis(100));

            // ── Broadcast join notice ───────────────────────────────
            // System messages are encrypted by the server; chat
            // messages are relayed as opaque ciphertext (never touched).
            let join_msg = encrypt_system_message(&format!("{} joined", username), &key);
            clients
                .lock()
                .unwrap()
                .values()
                .for_each(|tx| { tx.send(join_msg.clone()).ok(); });
            /*
           ## Breaking It Down

### Lines 2-5 — Broadcast to everyone

clients.lock()
```
`clients` is `Arc<Mutex<HashMap<...>>>`. `.lock()` acquires the mutex — blocks until no other thread holds it. Returns `Result<MutexGuard>`.

```rust
.unwrap()
```
Extracts the `MutexGuard` — panics only if another thread panicked while holding the lock (rare). The guard gives you access to the inner `HashMap` and **automatically releases the lock when it goes out of scope**.

```rust
.values()
```
Iterates over the `HashMap` values only — ignoring the username keys. Each value is a `tx` (a `Sender<Vec<u8>>`), the channel handle for one connected client.

```rust
.for_each(|tx| { tx.send(join_msg.clone()).ok(); });
```
For **every** connected client, send them the join message.

`.clone()` is necessary because `send()` takes ownership of the value, and you're sending to multiple recipients — so each needs their own copy. In F# this wouldn't stand out because immutable data is freely shared, but in Rust ownership means one sender would "consume" the message without cloning.

`.ok()` discards the Result — if a client's channel is broken we just silently skip them.

---

### The F# equivalent would look roughly like

```fsharp
let joinMsg = encryptSystemMessage (sprintf "%s joined" username) key

clients
|> Map.values
|> Seq.iter (fun tx -> tx.Post(joinMsg))
```

The main conceptual difference is just the `lock/unwrap` dance that F# doesn't need because it doesn't have Rust's shared-state threading model.
*/


            // ── Relay loop: forward ciphertext verbatim ─────────────
            // The server never decrypts chat messages — it reads each
            // framed blob and fans it out to every other connected client.
            std::iter::from_fn(|| read_message(&mut stream).ok())
                .for_each(|encrypted| {
                    clients
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .iter()
                        .filter(|(name, _)| *name != &username)
                        .for_each(|(_, tx)| { tx.send(encrypted.clone()).ok(); });
                });
            /*
            The most idiomatic choice for a chat server is probably unwrap_or_else(|p| p.into_inner())
             — it means "I don't care if another thread panicked, give me the lock anyway."
            */

            // ── Cleanup + broadcast leave notice ───────────────────
            // Remove the client from the map first so the leave message
            // is not echoed back to the departing client's (now closed) stream.
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

    /// Derives a secretbox key from a passphrase and a salt using Argon2id.
    ///
    /// The salt is generated once on the server at startup and sent to
    /// every client in plaintext before any encrypted traffic begins.
    /// Salt does not need to be secret — its purpose is to ensure that
    /// even identical passphrases produce different keys per deployment.
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
    /*
    sodiumoxide::init() initializes the underlying libsodium C library. Concretely it does two things:
    Seeding the random number generator — libsodium needs a cryptographically secure RNG (for generating nonces, salts, keys, etc.). On Linux this typically means reading from /dev/urandom or using the getrandom() syscall. This has to happen explicitly before any crypto operations.
    Thread safety setup — it ensures the library is safe to use from multiple threads. Without this call, concurrent calls to libsodium functions could race on internal state.
    */

    let passphrase = prompt_passphrase()?;

    // Generate a fresh random salt once at server startup.
    // Every client that connects receives this salt in plaintext
    // so they can derive the same key from the shared passphrase.
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