// Compute sha1 of [`msg`].
pub fn sha1(msg: &[u8]) -> [u8; 20] {
    let padded_msg = [msg, &sha1_pad(msg)].concat();
    sha1_with_state(
        &padded_msg,
        [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
    )
}

// Compute sha1 of [`msg`], starting with specific internal [`state`].
// This function does NOT add padding. Make sure [`msg`] is padded before calling this
// function, or just use `sha1`.
pub fn sha1_with_state(msg: &[u8], mut state: [u32; 5]) -> [u8; 20] {
    // msg length should be a multiple of 512 bits
    assert_eq!(msg.len() % 64, 0);

    let blocks = unsafe { msg.as_chunks_unchecked::<64>() };
    for &block in blocks {
        // message schedule
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        // working variables
        let [mut a, mut b, mut c, mut d, mut e] = state;

        // main loop
        for i in 0..80 {
            let (f, k) = if i <= 19 {
                ((b & c) | (!b & d), 0x5a827999)
            } else if i >= 20 && i <= 39 {
                (b ^ c ^ d, 0x6ED9EBA1)
            } else if i >= 40 && i <= 59 {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDC)
            } else if i >= 60 && i <= 79 {
                (b ^ c ^ d, 0xCA62C1D6)
            } else {
                unreachable!()
            };

            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    let mut digest = [0u8; 20];
    for i in 0..5 {
        digest[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_be_bytes());
    }
    digest
}

// Returns the padding bytes that should be appended to the message before feeding to `sha1`.
pub fn sha1_pad(msg: &[u8]) -> Vec<u8> {
    let mut padding = vec![];

    // append the bit '1'
    padding.push(0x80);

    // append zeros until (length in bits) % 512 == 448
    while (msg.len() + padding.len()) % 64 != 56 {
        padding.push(0);
    }

    // append original message length (in bits) as 64-bit big-endian integer
    padding.extend_from_slice(&u64::to_be_bytes((msg.len() * 8) as u64));

    // total length should now be a multiple of 512 bits
    assert!((msg.len() + padding.len()) % 64 == 0);

    padding
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::encoding::{hex_decode, utf8_decode};

    #[test]
    fn sha1_example() {
        let msg = utf8_decode("The quick brown fox jumps over the lazy dog");

        let digest = sha1(&msg);
        assert_eq!(
            digest.to_vec(),
            hex_decode("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")
        );
    }
}
