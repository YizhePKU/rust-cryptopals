#![feature(slice_as_chunks)]

use std::sync::OnceLock;

use crypto::{
    encoding::{utf8_decode, utf8_encode},
    sha1::{sha1, sha1_pad, sha1_with_state},
};

static KEY: OnceLock<[u8; 16]> = OnceLock::new();

fn prefix_sha1_mac_oracle() -> [u8; 20] {
    let key = KEY.get_or_init(|| rand::random());
    let msg = utf8_decode(
        "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon",
    );
    sha1(&[key as &[u8], &msg].concat()) // SHA1(key || message)
}

fn check_mac_oracle(msg: &[u8], mac: &[u8; 20]) -> bool {
    let key = KEY.get_or_init(|| rand::random());
    mac == &sha1(&[key as &[u8], &msg].concat())
}

fn main() {
    let msg = utf8_decode(
        "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon",
    );
    let mac = prefix_sha1_mac_oracle();

    assert!(check_mac_oracle(&msg, &mac));

    // glue padding (assuming key size is 16 bytes)
    let key = [0u8; 16];
    let glue_padding = sha1_pad(&[&key as &[u8], &msg].concat());

    // new message
    let new_msg = utf8_decode(";admin=true");

    // The complete message is (key || original-message || glue-padding || new-message || real-padding).
    let mut complete_msg = [&key as &[u8], &msg, &glue_padding, &new_msg].concat();
    let real_padding = sha1_pad(&complete_msg);
    complete_msg.extend_from_slice(&real_padding);

    // calculate new mac using length extension, by feeding (new-message || real-padding)
    let blocks = unsafe { mac.as_chunks_unchecked::<4>() };
    let state = [
        u32::from_be_bytes(blocks[0]),
        u32::from_be_bytes(blocks[1]),
        u32::from_be_bytes(blocks[2]),
        u32::from_be_bytes(blocks[3]),
        u32::from_be_bytes(blocks[4]),
    ];
    let new_mac = sha1_with_state(&[&new_msg as &[u8], &real_padding].concat(), state);

    // now (original-message || glue-padding || new-message) should pass the check with new_mac
    let payload = [&msg as &[u8], &glue_padding, &new_msg].concat();
    println!("Payload: {}", utf8_encode(&payload));
    assert!(check_mac_oracle(&payload, &new_mac));
}
