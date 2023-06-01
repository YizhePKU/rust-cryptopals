use crypto::encoding::hex_decode;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{BufRead, BufReader},
};

fn main() {
    let file = File::open("data/s1r8.txt").unwrap();
    for line in BufReader::new(file).lines() {
        let line = line.unwrap();
        let bytes = hex_decode(&line);
        assert!(bytes.len() % 16 == 0);

        let mut blocks = BTreeSet::new();
        for i in 0..bytes.len() / 16 {
            let block = &bytes[i * 16..(i + 1) * 16];
            if blocks.contains(block) {
                println!("ECB detected, here's the bytes.");
                println!("{bytes:?}");
                return;
            } else {
                blocks.insert(block);
            }
            println!("ECB not detected.");
        }
    }
}
