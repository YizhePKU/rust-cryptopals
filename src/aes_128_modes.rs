use crate::{
    aes_128::{aes_128_cipher, inv_aes_128_cipher},
    error::CryptoError,
    utils::{inv_pkcs7, pkcs7},
};

pub fn aes_128_ecb(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut data = pkcs7(data);
    assert!(data.len() % 16 == 0);

    let len = data.len();
    for i in 0..len / 16 {
        aes_128_cipher(key, (&mut data[i * 16..(i + 1) * 16]).try_into().unwrap());
    }
    data
}

pub fn inv_aes_128_ecb(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    assert!(data.len() % 16 == 0);

    let mut data = data.to_owned();
    let len = data.len();
    for i in 0..len / 16 {
        inv_aes_128_cipher(key, (&mut data[i * 16..(i + 1) * 16]).try_into().unwrap());
    }

    inv_pkcs7(&data)
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    static ANYBYTE: prop::num::u8::Any = prop::num::u8::ANY;

    proptest! {
        #[test]
        fn aes_128_ecb_roundtrip(key in [ANYBYTE; 16], data in prop::collection::vec(ANYBYTE, 0..100)) {
            let data2 = aes_128_ecb(&key, &data);
            let data3 = inv_aes_128_ecb(&key, &data2).unwrap();
            assert_eq!(data, data3);
        }
    }
}
