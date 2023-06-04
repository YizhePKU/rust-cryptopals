#![feature(slice_as_chunks)]

use crypto::{
    aes_128_modes::{aes_128_cbc, inv_aes_128_cbc},
    encoding::{b64_decode, utf8_encode}, utils::inv_pkcs7,
};
use rand::Rng;
use std::sync::OnceLock;

static KEY: OnceLock<[u8; 16]> = OnceLock::new();

fn encryption_oracle() -> (Vec<u8>, [u8; 16]) {
    let texts: Vec<Vec<u8>> = std::fs::read_to_string("data/s3r17.txt")
        .unwrap()
        .split('\n')
        .map(b64_decode)
        .collect();
    let idx = rand::thread_rng().gen_range(0..texts.len());
    let text = &texts[idx];

    let key = KEY.get_or_init(|| rand::random());
    let iv = rand::random();

    (aes_128_cbc(key, &iv, text), iv)
}

fn padding_oracle(iv: &[u8; 16], ciphertext: &[u8]) -> bool {
    let key = KEY.get_or_init(|| rand::random());
    inv_aes_128_cbc(key, iv, ciphertext).is_ok()
}

fn decrypt_block(iv: &[u8; 16], cipherblock: &[u8; 16]) -> [u8; 16] {
    let mut plainblock = [0; 16];
    'outer: for i in (0..16).rev() {
        let pad = (16 - i) as u8;

        // set the known bytes to `pad`
        let mut iv = iv.clone();
        for j in (i + 1)..16 {
            iv[j] ^= plainblock[j] ^ pad;
        }

        // try all possible values for plainblock[i]
        for byte in 0..=255 {
            let mut iv = iv.clone();
            iv[i] ^= byte ^ pad;
            if padding_oracle(&iv, cipherblock) {
                // scamble the previous byte to remove the 1/256 chance of false positive
                if i > 0 {
                    iv[i - 1] ^= 0xcd;
                }
                // re-test
                if padding_oracle(&iv, cipherblock) {
                    // good padding, plainblock[i] == byte
                    plainblock[i] = byte;
                    continue 'outer;
                }
            }
        }

        unreachable!()
    }

    plainblock
}

fn main() {
    let (ciphertext, iv) = encryption_oracle();
    let cipherblocks = unsafe { ciphertext.as_chunks_unchecked::<16>() };
    let mut plaintext = vec![];
    for i in 0..cipherblocks.len() {
        let iv = if i == 0 { iv } else { cipherblocks[i - 1] };
        let cipherblock = cipherblocks[i];
        let plainblock = decrypt_block(&iv, &cipherblock);
        plaintext.extend_from_slice(&plainblock);
    }

    println!("{}", utf8_encode(&inv_pkcs7(&plaintext).unwrap()));
}

#[cfg(test)]
mod test {
    use super::*;
    use crypto::utils::inv_pkcs7;
    use proptest::prelude::*;

    static ANYBYTE: prop::num::u8::Any = prop::num::u8::ANY;

    proptest! {
        #[test]
        fn can_decrypt_block(iv in [ANYBYTE; 16], plainblock in [ANYBYTE; 10]) {
            let key = KEY.get_or_init(|| rand::random());
            let cipherblock = aes_128_cbc(key, &iv, &plainblock);

            let result = decrypt_block(&iv, &cipherblock[..16].try_into().unwrap());
            assert_eq!(inv_pkcs7(&result).unwrap(), plainblock);
        }
    }
}
