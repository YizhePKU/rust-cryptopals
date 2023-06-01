use crypto::{
    aes_128_modes::inv_aes_128_ecb,
    encoding::{b64_decode, utf8_decode, utf8_encode},
};

fn main() {
    let bytes = b64_decode(&std::fs::read_to_string("data/s1r7.txt").unwrap());
    let key = utf8_decode("YELLOW SUBMARINE").try_into().unwrap();

    let text = inv_aes_128_ecb(&key, &bytes).unwrap();
    println!("{}", utf8_encode(&text));
}
