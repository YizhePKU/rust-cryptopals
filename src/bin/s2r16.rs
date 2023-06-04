use crypto::{
    aes_128_modes::{aes_128_cbc, inv_aes_128_cbc},
    encoding::{utf8_decode, utf8_encode},
    utils::xor_inplace,
};
use std::sync::OnceLock;

static KEY: OnceLock<[u8; 16]> = OnceLock::new();
static IV: OnceLock<[u8; 16]> = OnceLock::new(); // fixed IV

fn create_query_oracle(input: &str) -> Vec<u8> {
    let key = KEY.get_or_init(|| rand::random());
    let iv = IV.get_or_init(|| rand::random());

    let encoded_input = urlencoding::encode(input).into_owned();
    let data = utf8_decode(&format!(
        "comment1=cooking%20MCs;userdata={encoded_input};comment2=%20like%20a%20pound%20of%20bacon"
    ));
    aes_128_cbc(key, iv, &data)
}

fn check_query_oracle(data: &[u8]) -> bool {
    let key = KEY.get_or_init(|| rand::random());
    let iv = IV.get_or_init(|| rand::random());

    let data = inv_aes_128_cbc(key, iv, data).unwrap();
    let text = utf8_encode(&data);
    println!("{}", text);
    text.contains(";admin=true;")
}

fn main() {
    // [..............][..............][..............][..............][..............][..............][..............]
    // comment1=cooking%20MCs;userdata=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;comment2=%20like%20a%20pound%20of%20bacon
    //                                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    let mut query = create_query_oracle("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    // [..............]
    // ;admin=true;
    //             ^^^^ \x00, not actual space
    let payload1 = utf8_decode(";admin=true;\x00\x00\x00\x00");
    let payload2 = utf8_decode("AAAAAAAAAAAAAAAA");

    xor_inplace(&mut query[32..48], &payload1);
    xor_inplace(&mut query[32..48], &payload2);
    println!("{}", check_query_oracle(&query));
}
