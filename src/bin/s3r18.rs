use crypto::{encoding::{b64_decode, utf8_decode, utf8_encode}, aes_128_modes::aes_128_ctr};

fn main() {
    let ciphertext = b64_decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");

    let key = utf8_decode("YELLOW SUBMARINE").try_into().unwrap();
    let nonce = 0;
    let plaintext = aes_128_ctr(&key, nonce, &ciphertext);

    println!("{}", utf8_encode(&plaintext));
}