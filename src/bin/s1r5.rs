use crypto::encoding::{hex_encode, utf8_decode};

fn repeating_key_xor(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = bytes.to_owned();
    for i in 0..result.len() {
        result[i] ^= key[i % key.len()];
    }
    result
}

fn main() {
    let r = repeating_key_xor(
        &utf8_decode("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"),
        &utf8_decode("ICE"),
    );
    println!("{}", hex_encode(&r));
}
