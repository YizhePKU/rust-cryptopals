use base64::{engine::general_purpose::STANDARD, Engine};

pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn hex_decode(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap()
}

pub fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn b64_decode(text: &str) -> Vec<u8> {
    // remove whitespace
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD.decode(text).unwrap()
}

pub fn utf8_encode(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

pub fn utf8_decode(text: &str) -> Vec<u8> {
    text.as_bytes().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    static ANYBYTE: prop::num::u8::Any = prop::num::u8::ANY;

    #[test]
    fn cryptopals_s1c1() {
        let bytes = hex_decode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let text = b64_encode(&bytes);
        assert_eq!(
            text,
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    proptest! {
        #[test]
        fn hex_roundtrip(bytes in [ANYBYTE; 40]) {
            let hex = hex_encode(&bytes);
            let bytes2 = hex_decode(&hex);
            assert_eq!(&bytes, bytes2.as_slice());
        }

        #[test]
        fn b64_roundtrip(bytes in [ANYBYTE; 40]) {
            let b64 = b64_encode(&bytes);
            let bytes2 = b64_decode(&b64);
            assert_eq!(&bytes, bytes2.as_slice());
        }
    }
}
