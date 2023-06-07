use std::sync::OnceLock;

use crypto::{aes_128_modes::aes_128_ctr, encoding::b64_decode};

static KEY: OnceLock<[u8; 16]> = OnceLock::new();
static NONCE: OnceLock<u64> = OnceLock::new();

fn load_file_oracle() -> Vec<u8> {
    let bytes = b64_decode(&std::fs::read_to_string("data/s4r25.txt").unwrap());
    let key = KEY.get_or_init(|| rand::random());
    let nonce = NONCE.get_or_init(|| rand::random());
    aes_128_ctr(key, *nonce, &bytes)
}

fn edit_oracle(ciphertext: &[u8], offset: usize, newtext: &[u8]) -> Vec<u8> {
    assert!(offset + newtext.len() < ciphertext.len());

    let key = KEY.get_or_init(|| rand::random());
    let nonce = NONCE.get_or_init(|| rand::random());

    let mut plaintext = aes_128_ctr(key, *nonce, ciphertext);
    plaintext[offset..offset + newtext.len()].copy_from_slice(newtext);
    aes_128_ctr(key, *nonce, &plaintext) // nonce reuse!
}

fn main() {
    // "Random access" CTR is broken because of the nonce reuse.
    // By supplying zeros as newtext, we can recover the keystream.
}
