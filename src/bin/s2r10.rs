use crypto::{
    aes_128_modes::inv_aes_128_cbc,
    encoding::{b64_decode, utf8_decode, utf8_encode},
};

fn main() {
    let bytes = b64_decode(&std::fs::read_to_string("data/s2r10.txt").unwrap());
    let key = utf8_decode("YELLOW SUBMARINE").try_into().unwrap();
    let iv = [0; 16];
    let text = inv_aes_128_cbc(&key, &iv, &bytes).unwrap();
    println!("{}", utf8_encode(&text));
}
