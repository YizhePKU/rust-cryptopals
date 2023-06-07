// MT19937 implementation based on "A C-program for MT19937, with initialization improved"
// by Takuji Nishimura and Makoto Matsumoto, 2002/1/26.
// http://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/MT2002/CODES/mt19937ar.c

const N: usize = 624;
const M: usize = 397;
const A: u32 = 0x9908b0df;
const UPPER_MASK: u32 = 0x80000000;
const LOWER_MASK: u32 = 0x7fffffff;

#[derive(Debug, Clone)]
pub struct Mt19937 {
    state: Vec<u32>,
}

impl Mt19937 {
    pub fn new(seed: u32) -> Self {
        assert_ne!(seed, 0);

        let mut state = vec![0; N];
        state[0] = seed;
        for i in 1..N {
            state[i] = (state[i - 1] ^ (state[i - 1] >> 30)).wrapping_mul(1812433253) + (i as u32);
        }
        Self { state }
    }

    pub fn gen(&mut self) -> u32 {
        fn matrix(x: u32) -> u32 {
            if x & 1 == 0 {
                x >> 1
            } else {
                (x >> 1) ^ A
            }
        }

        let k = self.state.len() - N;

        // recurrence
        let x = self.state[k + M]
            ^ matrix((self.state[k] & UPPER_MASK) | (self.state[k + 1] & LOWER_MASK));

        self.state.push(x);

        // tempering
        let mut y = x;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c5680;
        y ^= (y << 15) & 0xefc60000;
        y ^= y >> 18;

        y
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn mt19937_seed_5489() {
        let mut mt19937 = Mt19937::new(5489);
        let mut result = [0; 10];
        for i in 0..10 {
            result[i] = mt19937.gen();
        }
        let answer = [
            0xD091BB5C, 0x22AE9EF6, 0xE7E1FAEE, 0xD5C31F79, 0x2082352C, 0xF807B7DF, 0xE9D30005,
            0x3895AFE1, 0xA1E24BBA, 0x4EE4092B,
        ];

        assert_eq!(result, answer);
    }
}
