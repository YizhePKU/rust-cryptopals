fn main() {
    // Since Unix timestamp only keeps track of the time in seconds, we can simply
    // bruteforce the seed by trying all seeds from time() - 5000 up to time() + 5000.
    // Moral of the story: don't seed with time(), use /dev/urandom.
}
