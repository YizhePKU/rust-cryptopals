#![feature(slice_as_chunks)]

use std::{sync::OnceLock, vec};

use crypto::{
    aes_128_modes::aes_128_ecb,
    encoding::{b64_decode, utf8_encode},
};

// Computes AES-128-ECB(data || secret, unknown-key)
fn ecb_oracle(data: &[u8]) -> Vec<u8> {
    static LOCK: OnceLock<[u8; 16]> = OnceLock::new();

    let key = LOCK.get_or_init(|| rand::random());
    let secret = b64_decode(&std::fs::read_to_string("data/s2r12.txt").unwrap());
    aes_128_ecb(key, &[data, &secret].concat())
}

fn first_n<T, const N: usize>(slice: &[T]) -> &[T; N] {
    assert!(slice.len() >= N);
    slice[..N].try_into().unwrap()
}

fn last_n<T, const N: usize>(slice: &[T]) -> &[T; N] {
    assert!(slice.len() >= N);
    slice[slice.len() - N..].try_into().unwrap()
}

fn decrypt_last_byte(cipherblock: &[u8; 16], known_bytes: &[u8; 15]) -> Option<u8> {
    for byte in 0..=255 {
        let plainblock = [known_bytes as &[u8], &[byte]].concat();
        if &ecb_oracle(&plainblock)[..16] == cipherblock {
            return Some(byte);
        }
    }
    None
}

// Decrypt secret[index] from the oracle, given secret[..index]
// When index == secret.len(), it will return 1 because of pkcs7
// When index == secret.len() + 1, it will return None, indicating end of secret
// The extra byte of 1 should be removed manually.
fn decrypt_byte(index: usize, known_bytes: &[u8]) -> Option<u8> {
    assert_eq!(known_bytes.len(), index);

    // add padding so that data[index] is the last byte of a block
    let padding = vec![0; 15 - index % 16];
    let padded_bytes = [&padding, known_bytes].concat();

    // compute the block
    let ciphertext = ecb_oracle(&padding);
    let cipherblocks = unsafe { ciphertext.as_chunks_unchecked::<16>() };
    let cipherblock = &cipherblocks[index / 16];

    // find out the known bytes (which is 15 bytes before data[index])
    let known_bytes = last_n::<u8, 15>(&padded_bytes);

    decrypt_last_byte(cipherblock, known_bytes)
}

fn main() {
    let mut known_bytes = vec![];
    for index in 0.. {
        match decrypt_byte(index, &known_bytes) {
            Some(byte) => {
                known_bytes.push(byte);
                println!("{:?}", known_bytes);
            }
            None => {
                assert_eq!(known_bytes[known_bytes.len() - 1], 1);
                known_bytes.pop(); // remove extra byte
                break;
            }
        }
    }
    let secret = utf8_encode(&known_bytes);
    println!("{}", secret);
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    static ANYBYTE: prop::num::u8::Any = prop::num::u8::ANY;

    proptest! {
        #[test]
        fn can_decrypt_last_byte(plainblock in [ANYBYTE; 16]) {
            let ciphertext = ecb_oracle(&plainblock);
            let cipherblock = first_n::<u8, 16>(&ciphertext);
            let last_byte = decrypt_last_byte(&cipherblock, first_n::<u8, 15>(&plainblock)).unwrap();
            assert_eq!(last_byte, plainblock[15]);
        }
    }
}
