Educational code for studying Rust syntax. Although it compiles and works, do not use the mostly vibe-coded code in production under any circumstances as it may contain flaws and hidden problems.

************************

February 26, 2026

‪An answer for barrett ✨ ‪@barretts.club


My percieved problem with the PM ergonomics (not considering the "classic" `if-else` construct here) is that there are too many (syntactically inconsistent, IMHO) control flow features - unlike the F# alternatives:

1) classing pattern matching `(Ok(...) =>, Err(...) =>)`  

2) if-let concept
```
if let Some(max) = config_max {
    println!("The maximum is configured to be {max}");
}
```

3) let...else concept 
```
fn describe_state_quarter(coin: Coin) -> Option<String> {
    let Coin::Quarter(state) = coin else {
        return None;
    };

    if state.existed_in(1900) {
        Some(format!("{state:?} is pretty old, for America!"))
    } else {
        Some(format!("{state:?} is relatively new."))
    }
}
```

4) the ? operator
```
fn read_message(reader: &mut impl Read) -> io::Result<Vec<u8>> {        
      let mut len_buf = [0u8; 4];         
      reader.read_exact(&mut len_buf)?;        
      let mut buf = vec![0u8; u32::from_be_bytes(len_buf) as usize];
      reader.read_exact(&mut buf)?;
      Ok(buf)
  }
 ```

6)  "unwrap-or-early-return"
```
let username = 
    match read_message(&mut stream)
        .ok()                
        .and_then(|msg| decrypt_username(&msg, &key))
            
{
   Some(name) => name,
   None => return, 
};
```

In F#, you mostly choose one of these two styles for all 5 aforementioned cases (pseudocode because of type inconsistency here). Or "classic" pattern matching if not possible/not practical to choose. The same for the Result type (`result {}`).
```
let username = 
    readMessage stream
    |> Option.ofResult
    |> Option.bind (fun msg -> decryptUsername msg key)
    |> Option.defaultWith (fun () -> return ())

let username = 
    option {
           let! msg = readMessage stream |> Option.ofResult         
           return! decryptUsername msg key
       } |> Option.defaultWith (fun () -> return ())
```
Maybe the creators of Rust should have drawn inspiration from F# syntax and ergonomics - not only for PM, but for iterators and actor models as well.

I myself would contemplate like this during creating the Rust pattern matching ergonomics:

*Does the ownership/borrowing concept allow me to use CEs or monadic composition?*

*Probably not, so let's leave only two concepts - pure pattern matching and the ?/Ok() structure (refactored as `?/OptionOfResult()` :-)).*

*Does the ownership/borrowing concept allow me to use at least option/result CEs like this?*
`option<T>`, `option<&T>`, `option<&mut T>`, `result<T>`, `result<&T>`, `result<&mut T>`

*If so, let's use those, and for all other combinations pure pattern matching will be used. If not, stick with the aforementioned `?/OptionOfResult()`.*

To eliminate pyramids of doom, I am a strong proponent of monadic composition, monadic CEs, monad-inspired custom CEs and ROP-style function composition with pattern matching left to bare minimum (and with the if-else construct totally banned in my F# code).

But once the Rust creators chose to implement the Result/Option types (enums) where pattern matching leading to pyramids of doom is the necessary evil much like the borrow checker clashing with the FP-style dealing with the pyramids of doom :-), I think the "classic" pattern matching might be more readable than the "Malbolge-style" alternatives with `let...else` and friends. Despite the pyramids of doom.

But others may be of a different opinion, though. :-)
 



       
       


‬





