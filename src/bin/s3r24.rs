fn main() {
    // With a 16-bit key (the seed), no algorithm is secure.
    // We can generate all the 2^16 keystreams, XOR each one with ciphertext,
    // and check which one of them ends with 14 'A's.
}