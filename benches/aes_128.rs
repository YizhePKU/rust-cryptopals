use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crypto::aes_128::{aes_128_cipher, inv_aes_128_cipher};
use openssl::symm::{Cipher, Crypter, Mode};

pub fn bench_aes_128_cipher(c: &mut Criterion) {
    c.bench_function("aes_128_cipher", |b| {
        b.iter(|| {
            let key = [1; 16];
            let mut data = [2; 16];
            aes_128_cipher(black_box(&key), black_box(&mut data))
        })
    });
}

pub fn bench_inv_aes_128_cipher(c: &mut Criterion) {
    c.bench_function("inv_aes_128_cipher", |b| {
        b.iter(|| {
            let key = [1; 16];
            let mut data = [2; 16];
            inv_aes_128_cipher(black_box(&key), black_box(&mut data))
        })
    });
}

pub fn bench_openssl_aes_128_cipher(c: &mut Criterion) {
    c.bench_function("openssl_aes_128_cipher", |b| {
        let key = [1; 16];
        let input = [2; 16];
        let mut output = [0; 32];
        let mut encrypter =
            Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, black_box(&key), None).unwrap();
        encrypter.pad(false);

        b.iter(|| {
            encrypter
                .update(black_box(&input), black_box(&mut output))
                .unwrap();
            encrypter.finalize(black_box(&mut output)).unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_aes_128_cipher,
    bench_inv_aes_128_cipher,
    bench_openssl_aes_128_cipher
);
criterion_main!(benches);
