use crypto::{
    encoding::{b64_decode, utf8_encode},
    utils::xor,
};

fn hamming_distance(lhs: &[u8], rhs: &[u8]) -> u32 {
    assert_eq!(lhs.len(), rhs.len());

    let mut result = 0;
    for i in 0..lhs.len() {
        let mut diff = lhs[i] ^ rhs[i];
        while diff > 0 {
            result += (diff & 0x1) as u32;
            diff >>= 1;
        }
    }

    result
}

fn score(text: &[u8]) -> i32 {
    let mut score = 0;
    for byte in text {
        let byte = *byte;
        // A-Z
        if byte >= 0x41 && byte <= 0x5a {
            score += 1;
        }
        // a-z
        if byte >= 0x61 && byte <= 0x7a {
            score += 1;
        }
        // whitespace
        if byte == 0x20 {
            score += 1;
        }
    }
    score
}

fn repeating_key_xor(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = bytes.to_owned();
    for i in 0..result.len() {
        result[i] ^= key[i % key.len()];
    }
    result
}

fn main() {
    let bytes = b64_decode(&std::fs::read_to_string("data/s1r6.txt").unwrap());

    for keysize in 1..40 {
        let n = bytes.len() / keysize;

        let mut distance = 0;
        for i in 0..n - 1 {
            distance += hamming_distance(&bytes[..keysize], &bytes[i * keysize..(i + 1) * keysize]);
        }
        let avg_distance = distance as f64 / (keysize * n) as f64;

        println!("{keysize}: {avg_distance}");
    }

    // keysize is probably 29
    const KEYSIZE: usize = 29;
    let mut keys = [0; KEYSIZE];
    for i in 0..KEYSIZE {
        // transpose data blocks
        let mut block = vec![];
        let mut j = i;
        while j < bytes.len() {
            block.push(bytes[j]);
            j += KEYSIZE;
        }
        // break single block xor key
        let mut table: Vec<(i32, u8, String)> = vec![];
        for key in 0..=255 {
            let mask = vec![key; block.len()];
            let text = xor(&block, &mask);
            table.push((score(&text), key, utf8_encode(&text)));
        }
        table.sort();
        // take the best key and hope it's right
        keys[i] = table[table.len() - 1].1;
    }

    println!("Key: {keys:?}");
    println!(
        "Message: {}",
        utf8_encode(&repeating_key_xor(&bytes, &keys))
    );
}

#[cfg(test)]
mod test {
    use crypto::encoding::utf8_decode;

    use super::*;

    #[test]
    fn wokka() {
        let lhs = utf8_decode("this is a test");
        let rhs = utf8_decode("wokka wokka!!!");
        assert_eq!(hamming_distance(&lhs, &rhs), 37);
    }
}
