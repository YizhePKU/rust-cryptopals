use crypto::{
    encoding::{hex_decode, utf8_encode},
    utils::xor,
};

fn score(text: &[u8]) -> u32 {
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

fn main() {
    let input = hex_decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");

    let mut table: Vec<(u32, u8, String)> = vec![];
    for key in 0..=255 {
        let mask = vec![key; input.len()];
        let text = xor(&input, &mask);
        table.push((score(&text), key, utf8_encode(&text)));
    }

    table.sort();

    for (score, key, text) in table {
        println!("{score} {key} {text}");
    }
}
