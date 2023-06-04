use std::{collections::BTreeMap, sync::OnceLock};

use crypto::{
    aes_128_modes::{aes_128_ecb, inv_aes_128_ecb},
    encoding::{utf8_decode, utf8_encode},
};

fn parse_kv(s: &str) -> Option<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for kv in s.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            if v.contains('=') {
                return None;
            }
            map.insert(k.to_owned(), v.to_owned());
        } else {
            return None;
        }
    }
    Some(map)
}

static KEY: OnceLock<[u8; 16]> = OnceLock::new();

fn profile_for(email: &str) -> String {
    if email.contains('=') || email.contains('&') {
        panic!("Illegal character in email");
    }
    format!("email={email}&uid=10&role=user")
}

fn make_profile_oracle(email: &str) -> Vec<u8> {
    let key = KEY.get_or_init(|| rand::random());
    let ciphertext = utf8_decode(&profile_for(email));
    aes_128_ecb(key, &ciphertext)
}

fn check_profile_oracle(profile: &[u8]) -> BTreeMap<String, String> {
    let key = KEY.get_or_init(|| rand::random());
    let plaintext = inv_aes_128_ecb(key, profile).unwrap();
    parse_kv(&utf8_encode(&plaintext)).unwrap()
}

fn main() {
    // [..............][..............][..............]
    // email=AAAAAAAAAAAAA&uid=10&role=user
    let profile1 = make_profile_oracle("AAAAAAAAAAAAA");

    // [..............][..............][..............][..............]
    // email=AAAAAAAAAAadmin           &uid=10&role=user
    //                      ^^^^^^^^^^^ pkcs7 padding, not actual space
    let profile2 =
        make_profile_oracle("AAAAAAAAAAadmin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B");

    let profile3 = [&profile1[..32], &profile2[16..32]].concat();
    println!("{:?}", check_profile_oracle(&profile3));
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_kv() {
        let map = parse_kv("foo=bar&baz=qux&zap=zazzle").unwrap();
        let mut map2 = BTreeMap::new();
        map2.insert("foo".to_owned(), "bar".to_owned());
        map2.insert("baz".to_owned(), "qux".to_owned());
        map2.insert("zap".to_owned(), "zazzle".to_owned());
        assert_eq!(map, map2);
    }
}
