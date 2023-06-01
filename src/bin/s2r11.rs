use crypto::aes_128_modes::{aes_128_cbc, aes_128_ecb};
use rand::{thread_rng, Rng};

enum EncryptionType {
    Ecb,
    Cbc,
}

fn encryption_oracle(input: &[u8]) -> (Vec<u8>, EncryptionType) {
    let mut rng = thread_rng();
    let mut data = vec![];

    // prepend random bytes
    for _ in 0..rng.gen_range(5..=10) {
        data.push(rng.gen());
    }

    data.extend_from_slice(input);

    // append random bytes
    for _ in 0..rng.gen_range(5..=10) {
        data.push(rng.gen());
    }

    // choose between ECB and CBC
    if rng.gen_bool(0.5) {
        let key = rng.gen();
        (aes_128_ecb(&key, &data), EncryptionType::Ecb)
    } else {
        let key = rng.gen();
        let iv = rng.gen();
        (aes_128_cbc(&key, &iv, &data), EncryptionType::Cbc)
    }
}

fn main() {
    // Not sure what the challenge actually wants us to do.
    // Do we get to choose plaintext? If so, just choose all-zeros
    // and ECB will have repeating bytes in the cyphertext.
    // If not, this seems unsolvable?
}
