use crypto::{
    aes_128_modes::{aes_128_cbc, inv_aes_128_cbc},
    utils::xor,
};
use std::sync::OnceLock;

static KEY: OnceLock<[u8; 16]> = OnceLock::new();

fn encryption_oracle(data: &[u8]) -> Vec<u8> {
    let key = KEY.get_or_init(|| rand::random());
    aes_128_cbc(key, key, data)
}

fn decryption_oracle(data: &[u8]) -> Option<Vec<u8>> {
    let key = KEY.get_or_init(|| rand::random());
    let plaintext = inv_aes_128_cbc(key, key, data).unwrap();
    for byte in &plaintext {
        if byte & 0x80 > 0 {
            return Some(plaintext);
        }
    }
    None
}

fn main() {
    // AES_CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
    // C_1 = AES(P_1 ^ KEY)
    // INV_AES_CBC(C_1, 0, C_1) -> P'_1, P'_2, P'_3
    // P'_1 = INV_AES(C_1) ^ KEY = P_1
    // P'_3 = INV_AES(C_1) ^ 0 = P_1 ^ KEY
    let ciphertext = encryption_oracle(&[0; 80]);
    let plaintext = decryption_oracle(
        &[
            &ciphertext[..16],
            &[0; 16],
            &ciphertext[..16],
            &ciphertext[48..],
        ]
        .concat(),
    )
    .unwrap();
    let key = xor(&plaintext[..16], &plaintext[32..48]);
    assert_eq!(key, KEY.get().unwrap());
}
