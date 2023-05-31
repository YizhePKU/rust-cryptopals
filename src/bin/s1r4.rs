use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use crypto::{
    encoding::{hex_decode, utf8_encode},
    utils::xor,
};

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

fn main() {
    let file = File::open("data/s1r4.txt").unwrap();

    let mut table: Vec<(i32, u8, String)> = vec![];
    for line in BufReader::new(file).lines() {
        let bytes = hex_decode(&line.unwrap());
        for key in 0..=255 {
            let mask = vec![key; bytes.len()];
            let text = xor(&bytes, &mask);
            table.push((score(&text), key, utf8_encode(&text)));
        }
    }

    table.sort();

    for (score, key, text) in &table[table.len() - 50..] {
        println!("{score} {key} {text}");
    }
}
