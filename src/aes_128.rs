pub fn aes_128_cipher(key: &[u8; 16], data: &mut [u8; 16]) {
    const N_ROUND: usize = 10; // number of rounds

    // key expansion
    let round_keys = key_expansion_128(*key);

    add_round_key(data, round_keys[0]);

    for round in 1..N_ROUND {
        sub_bytes(data);
        shift_rows(data);
        mix_columns(data);
        add_round_key(data, round_keys[round]);
    }

    sub_bytes(data);
    shift_rows(data);
    add_round_key(data, round_keys[N_ROUND]);
}

pub fn inv_aes_128_cipher(key: &[u8; 16], data: &mut [u8; 16]) {
    const N_ROUND: usize = 10; // number of rounds

    // key expansion
    let round_keys = key_expansion_128(*key);

    add_round_key(data, round_keys[N_ROUND]);

    for round in (1..N_ROUND).rev() {
        inv_shift_rows(data);
        inv_sub_bytes(data);
        add_round_key(data, round_keys[round]);
        inv_mix_columns(data);
    }

    inv_shift_rows(data);
    inv_sub_bytes(data);
    add_round_key(data, round_keys[0]);
}

#[rustfmt::skip]
const S_BOX: [[u8; 16]; 16] = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16],
];

#[rustfmt::skip]
const INV_S_BOX: [[u8; 16]; 16] = [
    [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
    [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
    [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
    [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
    [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
    [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
    [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
    [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
    [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
    [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
    [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
    [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
    [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
    [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
    [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d],
];

fn sub_bytes(data: &mut [u8; 16]) {
    for i in 0..16 {
        data[i] = S_BOX[(data[i] >> 4) as usize][(data[i] & 0xf) as usize];
    }
}

fn inv_sub_bytes(data: &mut [u8; 16]) {
    for i in 0..16 {
        data[i] = INV_S_BOX[(data[i] >> 4) as usize][(data[i] & 0xf) as usize];
    }
}

fn shift_rows(data: &mut [u8; 16]) {
    #[rustfmt::skip]
    const TABLE: [usize; 16] = [
         0,  5, 10, 15,
         4,  9, 14,  3,
         8, 13,  2,  7,
        12,  1,  6, 11,
    ];

    let original = data.clone();
    for i in 0..16 {
        data[i] = original[TABLE[i]];
    }
}

fn inv_shift_rows(data: &mut [u8; 16]) {
    #[rustfmt::skip]
    const TABLE: [usize; 16] = [
         0, 13, 10,  7,
         4,  1, 14, 11,
         8,  5,  2, 15,
        12,  9,  6,  3,
    ];

    let original = data.clone();
    for i in 0..16 {
        data[i] = original[TABLE[i]];
    }
}

fn mix_columns(data: &mut [u8; 16]) {
    fn mul2(x: u8) -> u8 {
        // if the highest bit of x is 0, return x << 1
        // otherwise, return (x << 1) ^ 0b11011
        let magic = 0b11011 * (x >> 7); // this avoids timing leak, I checked ths assembly
        (x << 1) ^ magic
    }

    fn mul3(x: u8) -> u8 {
        x ^ mul2(x)
    }

    for c in 0..4 {
        let mut x = [0; 4];
        x.copy_from_slice(&data[4 * c..4 * (c + 1)]);
        let y = &mut data[4 * c..4 * (c + 1)];
        y[0] = mul2(x[0]) ^ mul3(x[1]) ^ x[2] ^ x[3];
        y[1] = x[0] ^ mul2(x[1]) ^ mul3(x[2]) ^ x[3];
        y[2] = x[0] ^ x[1] ^ mul2(x[2]) ^ mul3(x[3]);
        y[3] = mul3(x[0]) ^ x[1] ^ x[2] ^ mul2(x[3]);
    }
}

fn inv_mix_columns(data: &mut [u8; 16]) {
    fn mul2(x: u8) -> u8 {
        // if the highest bit of x is 0, return x << 1
        // otherwise, return (x << 1) ^ 0b11011
        let magic = 0b11011 * (x >> 7); // this avoids timing leak, I checked ths assembly
        (x << 1) ^ magic
    }

    fn mulb(x: u8) -> u8 {
        x ^ mul2(x) ^ mul2(mul2(mul2(x)))
    }

    fn muld(x: u8) -> u8 {
        x ^ mul2(mul2(x)) ^ mul2(mul2(mul2(x)))
    }

    fn mul9(x: u8) -> u8 {
        x ^ mul2(mul2(mul2(x)))
    }

    fn mule(x: u8) -> u8 {
        mul2(x) ^ mul2(mul2(x)) ^ mul2(mul2(mul2(x)))
    }

    for c in 0..4 {
        let mut x = [0; 4];
        x.copy_from_slice(&data[4 * c..4 * (c + 1)]);
        let y = &mut data[4 * c..4 * (c + 1)];
        y[0] = mule(x[0]) ^ mulb(x[1]) ^ muld(x[2]) ^ mul9(x[3]);
        y[1] = mul9(x[0]) ^ mule(x[1]) ^ mulb(x[2]) ^ muld(x[3]);
        y[2] = muld(x[0]) ^ mul9(x[1]) ^ mule(x[2]) ^ mulb(x[3]);
        y[3] = mulb(x[0]) ^ muld(x[1]) ^ mul9(x[2]) ^ mule(x[3]);
    }
}

fn add_round_key(data: &mut [u8; 16], round_key: [u8; 16]) {
    for i in 0..16 {
        data[i] ^= round_key[i];
    }
}

fn key_expansion_128(key: [u8; 16]) -> [[u8; 16]; 11] {
    const RCON: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

    fn sub_word(x: u32) -> u32 {
        unsafe {
            let bytes = std::mem::transmute::<u32, [u8; 4]>(x);
            std::mem::transmute::<[u8; 4], u32>([
                S_BOX[(bytes[0] >> 4) as usize][(bytes[0] & 0xf) as usize],
                S_BOX[(bytes[1] >> 4) as usize][(bytes[1] & 0xf) as usize],
                S_BOX[(bytes[2] >> 4) as usize][(bytes[2] & 0xf) as usize],
                S_BOX[(bytes[3] >> 4) as usize][(bytes[3] & 0xf) as usize],
            ])
        }
    }

    fn rot_word(x: u32) -> u32 {
        x.rotate_right(8)
    }

    let mut w = [0u32; 4 * 11];

    // Copy the key into the first four words of w.
    unsafe {
        w[..4].copy_from_slice(&std::mem::transmute::<[u8; 16], [u32; 4]>(key));
    }

    for i in 4..4 * 11 {
        if i % 4 == 0 {
            w[i] = sub_word(rot_word(w[i - 1])) ^ RCON[(i / 4) - 1] ^ w[i - 4];
        } else {
            w[i] = w[i - 1] ^ w[i - 4];
        }
    }

    unsafe { std::mem::transmute::<[u32; 4 * 11], [[u8; 16]; 11]>(w) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::symm::{encrypt, Cipher};
    use proptest::prelude::*;

    static ANYBYTE: prop::num::u8::Any = prop::num::u8::ANY;

    proptest! {
        #[test]
        fn doesnt_crash(key in [ANYBYTE; 16], mut data in [ANYBYTE; 16]) {
            aes_128_cipher(&key, &mut data);
        }

        #[test]
        fn aes_128_cipher_matches_openssl(key in [ANYBYTE; 16], mut data in [ANYBYTE; 16]) {
            let ciphertext_openssl = encrypt(Cipher::aes_128_ecb(), &key, None, &data).unwrap();
            assert_eq!(ciphertext_openssl.len(), 32); // PKCS#7 padding

            aes_128_cipher(&key, &mut data);
            assert_eq!(&data, &ciphertext_openssl[..16]);
        }

        #[test]
        fn inv_aes_128_cipher_openssl_roundtrip(key in [ANYBYTE; 16], data in [ANYBYTE; 16]) {
            let ciphertext_openssl = encrypt(Cipher::aes_128_ecb(), &key, None, &data).unwrap();
            assert_eq!(ciphertext_openssl.len(), 32); // PKCS#7 padding

            let mut data2 = [0; 16];
            data2.copy_from_slice(&ciphertext_openssl[..16]);
            inv_aes_128_cipher(&key, &mut data2);
            assert_eq!(data, data2);
        }

        #[test]
        fn aes_128_cipher_roundtrip(key in [ANYBYTE; 16], data in [ANYBYTE; 16]) {
            let mut data2 = data.clone();
            aes_128_cipher(&key, &mut data2);
            inv_aes_128_cipher(&key, &mut data2);
            assert_eq!(data, data2);
        }

        #[test]
        fn sub_bytes_roundtrip(data in [ANYBYTE; 16]) {
            let mut data2 = data.clone();
            sub_bytes(&mut data2);
            inv_sub_bytes(&mut data2);
            assert_eq!(data, data2);
        }

        #[test]
        fn shift_rows_roundtrip(data in [ANYBYTE; 16]) {
            let mut data2 = data.clone();
            shift_rows(&mut data2);
            inv_shift_rows(&mut data2);
            assert_eq!(data, data2);
        }

        #[test]
        fn mix_columns_roundtrip(data in [ANYBYTE; 16]) {
            let mut data2 = data.clone();
            mix_columns(&mut data2);
            inv_mix_columns(&mut data2);
            assert_eq!(data, data2);
        }
    }

    #[test]
    fn matches_openssl_input_all_zeros() {
        let key = [0; 16];
        let mut data = [0; 16];
        let ciphertext_openssl = encrypt(Cipher::aes_128_ecb(), &key, None, &data).unwrap();
        assert_eq!(ciphertext_openssl.len(), 32); // PKCS#7 padding

        aes_128_cipher(&key, &mut data);
        assert_eq!(&data, &ciphertext_openssl[..16]);
    }

    #[test]
    fn sub_bytes_example() {
        let mut data = [0x53; 16];
        sub_bytes(&mut data);
        assert_eq!(data, [0xed; 16]);
    }

    #[test]
    fn shift_rows_example() {
        #[rustfmt::skip]
        let mut data = [
             0,  1,  2,  3,
             4,  5,  6,  7,
             8,  9, 10, 11,
            12, 13, 14, 15,
        ];
        #[rustfmt::skip]
        let result = [
            0,  5, 10, 15,
            4,  9, 14,  3,
            8, 13,  2,  7,
           12,  1,  6, 11,
        ];
        shift_rows(&mut data);
        assert_eq!(data, result);
    }

    #[test]
    fn mix_columns_example() {
        #[rustfmt::skip]
        let mut data = [
            0xd4, 0xbf, 0x5d, 0x30,
            0xe0, 0xb4, 0x52, 0xae,
            0xb8, 0x41, 0x11, 0xf1,
            0x1e, 0x27, 0x98, 0xe5,
        ];
        #[rustfmt::skip]
       let result = [
            0x04, 0x66, 0x81, 0xe5,
            0xe0, 0xcb, 0x19, 0x9a,
            0x48, 0xf8, 0xd3, 0x7a,
            0x28, 0x06, 0x26, 0x4c,
       ];
        mix_columns(&mut data);
        assert_eq!(data, result);
    }

    #[test]
    fn key_expansion_128_example() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let round_one_key = [
            0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c,
            0x76, 0x05,
        ];
        let round_ten_key = [
            0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63,
            0x0c, 0xa6,
        ];

        let result = key_expansion_128(key);
        assert_eq!(result[1], round_one_key);
        assert_eq!(result[10], round_ten_key);
    }
}
