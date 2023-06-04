use crate::{
    aes_128::{aes_128_cipher, inv_aes_128_cipher},
    error::CryptoError,
    utils::{inv_pkcs7, pkcs7, xor_inplace},
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

pub fn aes_128_cbc(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut data = pkcs7(data);
    assert!(data.len() % 16 == 0);

    let blocks = unsafe { data.as_chunks_unchecked_mut::<16>() };
    let mut prev = iv;

    for block in blocks {
        xor_inplace(block, prev);
        aes_128_cipher(key, block);
        prev = block;
    }

    data
}

pub fn inv_aes_128_cbc(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    assert!(data.len() % 16 == 0);

    let mut result = data.to_owned();

    let blocks1 = unsafe { data.as_chunks_unchecked::<16>() };
    let blocks2 = unsafe { result.as_chunks_unchecked_mut::<16>() };

    for block in blocks2.iter_mut() {
        inv_aes_128_cipher(key, block);
    }

    xor_inplace(&mut blocks2[0], iv);
    for i in 1..blocks2.len() {
        xor_inplace(&mut blocks2[i], &blocks1[i - 1]);
    }

    inv_pkcs7(&result)
}

// format: 64 bits nouce + 64 bits block count (little endian)
pub fn aes_128_ctr(key: &[u8; 16], nonce: u64, data: &[u8]) -> Vec<u8> {
    let mut result = data.to_owned();

    for cnt in 0.. {
        let mut keyblock = [0; 16];
        keyblock[..8].copy_from_slice(&u64::to_le_bytes(nonce));
        keyblock[8..].copy_from_slice(&u64::to_le_bytes(cnt as u64));

        aes_128_cipher(key, &mut keyblock);

        let len = result.len();
        if len > (cnt + 1) * 16 {
            xor_inplace(&mut result[cnt * 16..(cnt + 1) * 16], &keyblock);
        } else {
            xor_inplace(&mut result[cnt * 16..], &keyblock[..len - cnt * 16]);
            break;
        }
    }

    result
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

        #[test]
        fn aes_128_cbc_roundtrip(key in [ANYBYTE; 16], iv in [ANYBYTE; 16], data in prop::collection::vec(ANYBYTE, 0..100)) {
            let data2 = aes_128_cbc(&key, &iv, &data);
            let data3 = inv_aes_128_cbc(&key, &iv, &data2).unwrap();
            assert_eq!(data, data3);
        }
    }
}
