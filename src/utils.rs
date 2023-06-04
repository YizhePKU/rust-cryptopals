use crate::error::CryptoError;

pub fn xor(lhs: &[u8], rhs: &[u8]) -> Vec<u8> {
    assert_eq!(lhs.len(), rhs.len());

    let mut result = vec![0; lhs.len()];
    for i in 0..lhs.len() {
        result[i] = lhs[i] ^ rhs[i];
    }
    result
}

pub fn xor_inplace(lhs: &mut [u8], rhs: &[u8]) {
    assert_eq!(lhs.len(), rhs.len());

    for i in 0..lhs.len() {
        lhs[i] ^= rhs[i];
    }
}

pub fn pkcs7(bytes: &[u8]) -> Vec<u8> {
    const K: usize = 16;

    let mut result = bytes.to_owned();
    let cnt = K - (bytes.len() % K);
    for _ in 0..cnt {
        result.push(cnt as u8);
    }

    result
}

pub fn inv_pkcs7(bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cnt = bytes[bytes.len() - 1] as usize;
    if cnt == 0 || cnt > 16 {
        return Err(CryptoError::PaddingError);
    }
    for i in 0..cnt {
        if bytes[bytes.len() - 1 - i] != cnt as u8 {
            return Err(CryptoError::PaddingError);
        }
    }
    Ok(bytes[..bytes.len() - cnt].to_owned())
}

pub fn first_n<T, const N: usize>(slice: &[T]) -> &[T; N] {
    assert!(slice.len() >= N);
    slice[..N].try_into().unwrap()
}

pub fn last_n<T, const N: usize>(slice: &[T]) -> &[T; N] {
    assert!(slice.len() >= N);
    slice[slice.len() - N..].try_into().unwrap()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::encoding::hex_decode;
    use proptest::prelude::*;

    #[test]
    fn cryptopals_s1c2() {
        let lhs = hex_decode("1c0111001f010100061a024b53535009181c");
        let rhs = hex_decode("686974207468652062756c6c277320657965");
        let result = hex_decode("746865206b696420646f6e277420706c6179");

        assert_eq!(xor(&lhs, &rhs), result);
    }

    proptest! {
        #[test]
        fn pkcs7_roundtrip(len in prop::num::u16::ANY) {
            let data = vec![0; len as usize];
            let data2 = inv_pkcs7(&pkcs7(&data)).unwrap();
            assert_eq!(data, data2);
        }
    }
}
